use crate::Blockchain;
use crate::Client;
use crate::Error;
use crate::error::ErrorContext;
use crate::swap_storage::SwapStorage;
use crate::utils::timeout_op;
use crate::wallet::BoardingWallet;
use crate::wallet::OnchainWallet;
use ark_core::ArkAddress;
use ark_core::ErrorContext as _;
use ark_core::Vtxo;
use ark_core::coin_select::select_vtxos;
use ark_core::intent;
use ark_core::send;
use ark_core::send::OffchainTransactions;
use ark_core::send::build_offchain_transactions;
use ark_core::send::sign_ark_transaction;
use ark_core::send::sign_checkpoint_transaction;
use ark_core::server::SubmitOffchainTxResponse;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::psbt;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;

/// Error message indicating a duplicated offchain transaction.
const DUPLICATED_OFFCHAIN_TX_ERROR: &str = "duplicated offchain tx";

impl<B, W, S> Client<B, W, S>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
    S: SwapStorage + 'static,
{
    /// Spend confirmed and pre-confimed VTXOs in an Ark transaction sending the given `amount` to
    /// the given `address`.
    ///
    /// The Ark transaction is built in collaboration with the Ark server. The outputs of said
    /// transaction will be pre-confirmed VTXOs.
    ///
    /// # Returns
    ///
    /// The [`Txid`] of the generated Ark transaction.
    pub async fn send_vtxo(&self, address: ArkAddress, amount: Amount) -> Result<Txid, Error> {
        // Recoverable VTXOs cannot be sent.
        let select_recoverable_vtxos = false;

        let spendable_vtxos = self
            .spendable_vtxos(select_recoverable_vtxos)
            .await
            .context("failed to get spendable VTXOs")?;

        // Run coin selection algorithm on candidate spendable VTXOs.
        let spendable_virtual_tx_outpoints = spendable_vtxos
            .iter()
            .flat_map(|(vtxos, _)| vtxos.clone())
            .map(|vtxo| ark_core::coin_select::VirtualTxOutPoint {
                outpoint: vtxo.outpoint,
                expire_at: vtxo.expires_at,
                amount: vtxo.amount,
            })
            .collect::<Vec<_>>();

        let selected_coins = select_vtxos(
            spendable_virtual_tx_outpoints,
            amount,
            self.server_info.dust,
            true,
        )
        .map_err(Error::from)
        .context("failed to select coins")?;

        // Keep track of selected VTXOs for potential retry.
        // We store (outpoint, amount, vtxo) tuples.
        let selected_vtxos_with_outpoints: Vec<(OutPoint, Amount, Vtxo)> = selected_coins
            .iter()
            .map(|virtual_tx_outpoint| {
                let vtxo = spendable_vtxos
                    .clone()
                    .into_iter()
                    .find_map(|(virtual_tx_outpoints, vtxo)| {
                        virtual_tx_outpoints
                            .iter()
                            .any(|v| v.outpoint == virtual_tx_outpoint.outpoint)
                            .then_some(vtxo)
                    })
                    .expect("to find matching default VTXO");

                (
                    virtual_tx_outpoint.outpoint,
                    virtual_tx_outpoint.amount,
                    vtxo,
                )
            })
            .collect();

        let vtxo_inputs = selected_vtxos_with_outpoints
            .iter()
            .map(|(outpoint, amount, vtxo)| {
                let (forfeit_script, control_block) = vtxo
                    .forfeit_spend_info()
                    .context("failed to get forfeit spend info")?;

                Ok(send::VtxoInput::new(
                    forfeit_script,
                    None,
                    control_block,
                    vtxo.tapscripts(),
                    vtxo.script_pubkey(),
                    *amount,
                    *outpoint,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let (change_address, _) = self.get_offchain_address()?;

        let OffchainTransactions {
            mut ark_tx,
            checkpoint_txs,
        } = build_offchain_transactions(
            &[(&address, amount)],
            Some(&change_address),
            &vtxo_inputs,
            &self.server_info,
        )
        .map_err(Error::from)
        .context("failed to build offchain transactions")?;

        let sign_fn = |_: &mut psbt::Input,
                       msg: secp256k1::Message|
         -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, self.kp());
            let pk = self.kp().x_only_public_key().0;

            Ok((sig, pk))
        };

        for i in 0..checkpoint_txs.len() {
            sign_ark_transaction(sign_fn, &mut ark_tx, i)?;
        }

        let ark_txid = ark_tx.unsigned_tx.compute_txid();

        // Try to submit the offchain transaction; if it fails with a duplicated tx error,
        // retrieve the pending transaction and continue with finalization.
        let res: SubmitOffchainTxResponse = match self
            .network_client()
            .submit_offchain_transaction_request(ark_tx, checkpoint_txs)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains(DUPLICATED_OFFCHAIN_TX_ERROR) {
                    self.retry_offchain_tx(&selected_vtxos_with_outpoints, sign_fn, ark_txid)
                        .await?
                } else {
                    return Err(Error::ark_server(e))
                        .context("failed to submit offchain transaction request");
                }
            }
        };

        self.finalize_offchain_tx(sign_fn, ark_txid, res).await
    }

    /// Retry an offchain transaction by retrieving pending transactions from the server.
    async fn retry_offchain_tx<F>(
        &self,
        selected_vtxos: &[(OutPoint, Amount, Vtxo)],
        sign_fn: F,
        expected_ark_txid: Txid,
    ) -> Result<SubmitOffchainTxResponse, Error>
    where
        F: Fn(
            &mut psbt::Input,
            secp256k1::Message,
        ) -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error>,
    {
        // Build intent inputs from the selected VTXOs.
        let intent_inputs = selected_vtxos
            .iter()
            .map(|(outpoint, amount, vtxo)| {
                let spend_info = vtxo
                    .forfeit_spend_info()
                    .context("failed to get forfeit spend info")?;

                Ok(intent::Input::new(
                    *outpoint,
                    vtxo.exit_delay(),
                    TxOut {
                        value: *amount,
                        script_pubkey: vtxo.script_pubkey(),
                    },
                    vtxo.tapscripts(),
                    spend_info,
                    false,
                    // Spendable VTXOs are never swept.
                    false,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let now = std::time::SystemTime::now();
        let now = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(Error::ad_hoc)
            .context("failed to compute now timestamp")?;
        let now = now.as_secs();

        // Create the get-pending-tx intent.
        let get_pending_tx_intent =
            intent::make_get_pending_tx_intent(&sign_fn, &sign_fn, now, intent_inputs)
                .map_err(Error::from)
                .context("failed to create get-pending-tx intent")?;

        // Call the get_pending_tx API.
        let pending_txs = self
            .network_client()
            .get_pending_tx(get_pending_tx_intent)
            .await
            .map_err(Error::ark_server)
            .context("failed to get pending transactions")?;

        // Find the pending transaction matching our expected txid.
        let pending_tx = pending_txs
            .into_iter()
            .find(|tx| tx.ark_txid == expected_ark_txid)
            .ok_or_else(|| {
                Error::ad_hoc(format!(
                    "pending transaction with txid {} not found",
                    expected_ark_txid
                ))
            })?;

        Ok(SubmitOffchainTxResponse {
            signed_ark_tx: pending_tx.signed_ark_tx,
            signed_checkpoint_txs: pending_tx.signed_checkpoint_txs,
        })
    }

    /// Finalize an offchain transaction by signing checkpoints and calling finalize.
    async fn finalize_offchain_tx<F>(
        &self,
        sign_fn: F,
        ark_txid: Txid,
        mut res: SubmitOffchainTxResponse,
    ) -> Result<Txid, Error>
    where
        F: Fn(
            &mut psbt::Input,
            secp256k1::Message,
        ) -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error>,
    {
        for checkpoint_psbt in res.signed_checkpoint_txs.iter_mut() {
            sign_checkpoint_transaction(&sign_fn, checkpoint_psbt)?;
        }

        timeout_op(
            self.inner.timeout,
            self.network_client()
                .finalize_offchain_transaction(ark_txid, res.signed_checkpoint_txs),
        )
        .await?
        .map_err(Error::ark_server)
        .context("failed to finalize offchain transaction")?;

        Ok(ark_txid)
    }
}
