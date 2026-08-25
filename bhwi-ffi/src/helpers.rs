//! Pure, device-free helpers: descriptor building, address derivation, PSBT inspection.

use std::str::FromStr;

use bhwi::bitcoin::bip32::{Fingerprint, Xpub};
use bhwi::bitcoin::secp256k1::Secp256k1;
use bhwi::bitcoin::{Address, Amount, NetworkKind, TxOut};
use bhwi::miniscript::{Descriptor, DescriptorPublicKey};

use crate::types::decode_psbt;
use crate::{AddressFormat, HwiError, Network};

/// Upper bound on a single `derive_addresses` call.
const MAX_DERIVE_COUNT: u32 = 1000;

#[derive(Clone, Debug, uniffi::Record)]
pub struct AddressEntry {
    pub index: u32,
    pub address: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct InputSummary {
    pub prev_txid: String,
    pub vout: u32,
    pub amount_sat: Option<u64>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct OutputSummary {
    pub address: Option<String>,
    pub amount_sat: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PsbtSummary {
    pub inputs: Vec<InputSummary>,
    pub outputs: Vec<OutputSummary>,
    pub fee_sat: Option<u64>,
}

/// Builds the standard multipath singlesig descriptor for an account xpub: the
/// `<0;1>` receive/change pair followed by a wildcard index.
///
/// (The literal `/` + `*` suffix is spelled out rather than written inline because
/// UniFFI copies doc comments verbatim and Kotlin block comments nest.)
#[uniffi::export]
pub fn build_singlesig_descriptor(
    xpub: String,
    fingerprint: String,
    origin_path: String,
    kind: AddressFormat,
    network: Network,
) -> Result<String, HwiError> {
    let parsed_xpub = Xpub::from_str(xpub.trim())
        .map_err(|_| HwiError::invalid("invalid extended public key"))?;
    let expected = NetworkKind::from(bhwi::bitcoin::Network::from(network));
    if parsed_xpub.network != expected {
        return Err(HwiError::invalid(
            "extended public key does not match the requested network",
        ));
    }
    let fingerprint = Fingerprint::from_str(fingerprint.trim())
        .map_err(|_| HwiError::invalid("invalid master fingerprint"))?;

    // Accept both `m/84'/0'/0'` and `84'/0'/0'`.
    let origin = origin_path
        .trim()
        .trim_start_matches('m')
        .trim_start_matches('/')
        .trim_end_matches('/');
    let key = if origin.is_empty() {
        format!("[{fingerprint}]{parsed_xpub}/<0;1>/*")
    } else {
        format!("[{fingerprint}/{origin}]{parsed_xpub}/<0;1>/*")
    };
    let descriptor = match kind {
        AddressFormat::Legacy => format!("pkh({key})"),
        AddressFormat::NestedSegwit => format!("sh(wpkh({key}))"),
        AddressFormat::NativeSegwit => format!("wpkh({key})"),
        AddressFormat::Taproot => format!("tr({key})"),
    };
    // Round-trip so callers never get an unparsable string back, and so the checksum
    // miniscript appends is the authoritative one.
    Descriptor::<DescriptorPublicKey>::from_str(&descriptor)
        .map(|d| d.to_string())
        .map_err(|e| HwiError::invalid(e.to_string()))
}

/// Derives receive (`change == false`) or change addresses from a descriptor.
///
/// Accepts either a multipath descriptor (as produced by [`build_singlesig_descriptor`])
/// or a single-branch descriptor, in which case only `change == false` is valid.
#[uniffi::export]
pub fn derive_addresses(
    descriptor: String,
    network: Network,
    change: bool,
    start: u32,
    count: u32,
) -> Result<Vec<AddressEntry>, HwiError> {
    if count > MAX_DERIVE_COUNT {
        return Err(HwiError::invalid(format!(
            "count must be at most {MAX_DERIVE_COUNT}"
        )));
    }
    let end = start
        .checked_add(count)
        .ok_or_else(|| HwiError::invalid("derivation index range overflows"))?;

    let parsed = Descriptor::<DescriptorPublicKey>::from_str(descriptor.trim())
        .map_err(|e| HwiError::invalid(e.to_string()))?;
    let branches = parsed
        .into_single_descriptors()
        .map_err(|e| HwiError::invalid(e.to_string()))?;
    let branch = branches
        .get(usize::from(change))
        .ok_or_else(|| HwiError::invalid("descriptor has no change branch"))?;

    let secp = Secp256k1::verification_only();
    let network = bhwi::bitcoin::Network::from(network);
    let mut entries = Vec::with_capacity(count as usize);
    for index in start..end {
        let address = branch
            .derive_at_index(index)
            .map_err(|e| HwiError::invalid(e.to_string()))?
            .derived_descriptor(&secp)
            .address(network)
            .map_err(|e| HwiError::invalid(e.to_string()))?;
        entries.push(AddressEntry {
            index,
            address: address.to_string(),
        });
    }
    Ok(entries)
}

/// Summarises a PSBT for a confirmation screen. Amounts come from the PSBT's own UTXO
/// data, so `amount_sat`/`fee_sat` are `None` when the PSBT does not carry them.
#[uniffi::export]
pub fn psbt_summary(psbt_base64: String, network: Network) -> Result<PsbtSummary, HwiError> {
    let psbt = decode_psbt(&psbt_base64)?;
    let network = bhwi::bitcoin::Network::from(network);

    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    let mut total_in: Option<Amount> = Some(Amount::ZERO);
    for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let utxo: Option<&TxOut> = psbt.inputs.get(index).and_then(|input| {
            input.witness_utxo.as_ref().or_else(|| {
                input
                    .non_witness_utxo
                    .as_ref()
                    .and_then(|tx| tx.output.get(txin.previous_output.vout as usize))
            })
        });
        total_in = match (total_in, utxo) {
            (Some(sum), Some(utxo)) => sum.checked_add(utxo.value),
            _ => None,
        };
        inputs.push(InputSummary {
            prev_txid: txin.previous_output.txid.to_string(),
            vout: txin.previous_output.vout,
            amount_sat: utxo.map(|utxo| utxo.value.to_sat()),
        });
    }

    let mut total_out = Some(Amount::ZERO);
    let outputs: Vec<OutputSummary> = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|txout| {
            total_out = total_out.and_then(|sum| sum.checked_add(txout.value));
            OutputSummary {
                address: Address::from_script(&txout.script_pubkey, network)
                    .ok()
                    .map(|address| address.to_string()),
                amount_sat: txout.value.to_sat(),
            }
        })
        .collect();

    let fee_sat = match (total_in, total_out) {
        (Some(input), Some(output)) => input.checked_sub(output).map(|fee| fee.to_sat()),
        _ => None,
    };

    Ok(PsbtSummary {
        inputs,
        outputs,
        fee_sat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const XPUB: &str = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";

    #[test]
    fn descriptor_round_trips_and_derives_both_branches() {
        let descriptor = build_singlesig_descriptor(
            XPUB.into(),
            "f5acc2fd".into(),
            "m/84'/1'/0'".into(),
            AddressFormat::NativeSegwit,
            Network::Testnet,
        )
        .expect("descriptor builds");
        assert!(descriptor.starts_with("wpkh([f5acc2fd/84'/1'/0']"));
        assert!(descriptor.contains("/<0;1>/*"));

        let receive = derive_addresses(descriptor.clone(), Network::Testnet, false, 0, 2).unwrap();
        let change = derive_addresses(descriptor, Network::Testnet, true, 0, 2).unwrap();
        assert_eq!(receive.len(), 2);
        assert_eq!(receive[0].index, 0);
        assert!(receive[0].address.starts_with("tb1q"));
        assert_ne!(receive[0].address, change[0].address);
    }

    #[test]
    fn descriptor_rejects_network_mismatch_and_derive_rejects_huge_counts() {
        assert!(matches!(
            build_singlesig_descriptor(
                XPUB.into(),
                "f5acc2fd".into(),
                "m/84'/0'/0'".into(),
                AddressFormat::NativeSegwit,
                Network::Bitcoin,
            ),
            Err(HwiError::InvalidInput { .. })
        ));

        let descriptor = build_singlesig_descriptor(
            XPUB.into(),
            "f5acc2fd".into(),
            "m/84'/1'/0'".into(),
            AddressFormat::NativeSegwit,
            Network::Testnet,
        )
        .unwrap();
        assert!(matches!(
            derive_addresses(descriptor, Network::Testnet, false, 0, MAX_DERIVE_COUNT + 1),
            Err(HwiError::InvalidInput { .. })
        ));
    }

    /// One P2WPKH input worth 10_000 sat, one 9_000 sat output: 1_000 sat fee.
    fn test_psbt() -> String {
        use bhwi::bitcoin::hashes::Hash;
        use bhwi::bitcoin::psbt::Psbt;
        use bhwi::bitcoin::{
            OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Witness, absolute::LockTime,
            transaction::Version,
        };

        let descriptor = build_singlesig_descriptor(
            XPUB.into(),
            "f5acc2fd".into(),
            "m/84'/1'/0'".into(),
            AddressFormat::NativeSegwit,
            Network::Testnet,
        )
        .unwrap();
        let address = derive_addresses(descriptor, Network::Testnet, false, 0, 1).unwrap()[0]
            .address
            .clone();
        let script = Address::from_str(&address)
            .unwrap()
            .assume_checked()
            .script_pubkey();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: script,
        });
        crate::types::encode_psbt(&psbt)
    }

    #[test]
    fn psbt_summary_reports_amounts_and_fee() {
        let summary = psbt_summary(test_psbt(), Network::Testnet).expect("summary");
        assert_eq!(summary.inputs.len(), 1);
        assert_eq!(summary.inputs[0].amount_sat, Some(10_000));
        assert_eq!(summary.outputs.len(), 1);
        assert_eq!(summary.outputs[0].amount_sat, 9_000);
        assert_eq!(summary.fee_sat, Some(1_000));
        assert!(summary.outputs[0].address.is_some());
    }
}
