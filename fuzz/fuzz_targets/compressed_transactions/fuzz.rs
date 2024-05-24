use compressed_transactions::{CompressedTransaction, CompressedInput, CompressedOutPoint};
use bitcoin::{ScriptBuf, Amount, PublicKey, TxIn, TxOut, Sequence, Txid, OutPoint, Witness, Transaction};
use bitcoin::secp256k1::{SecretKey, Secp256k1, All};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::transaction::Version;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode;
use bitcoin::key::secp256k1;
use honggfuzz::fuzz;
use std::cmp::max;
use std::io;


#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("No Witness Hash For Public Key")]
    NoWitnessHash(),
    #[error("Value was Out of Bounds")]
    ValOutBounds(),
    #[error("Bitcoin Core Consensus Error:\n{}", .0)]
    BitcoinConsensus(#[from] bitcoin::consensus::encode::Error),
    #[error("Bitcoin Key Error:\n{}", .0)]
    BitcoinKey(#[from] bitcoin::key::Error),
    #[error("Secp256k1 Error:\n{}", .0)]
    Secp256k1(#[from] secp256k1::Error),
    #[error("Bitcoin Sighash:\n{}", .0)]
    BitcoinSighash(#[from] bitcoin::sighash::Error),
    #[error("IO Error:\n{}", .0)]
    Io(#[from] std::io::Error),
    #[error("Compressed Transaction Error:\n{}", .0)]
    CompressedTransactionError(#[from] compressed_transactions::Error),

}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            let mut copy = data;
            match do_test(&mut copy) {
                Ok(()) => (),
                Err(Error::BitcoinConsensus(encode::Error::Io(err))) if err.kind() == io::ErrorKind::UnexpectedEof => return,
                Err(err) => { panic!("{:?}", err); }
            }
        });
    }
}

fn get_script(script_type: u8, sk: SecretKey, ctx: &Secp256k1<All>) -> Result<(ScriptBuf, Option<ScriptBuf>), Error> {
    let pubkey = sk.public_key(ctx);
    Ok(match script_type {
        0 => (ScriptBuf::new_p2pk(&PublicKey::new(pubkey)), None),
        1 => (ScriptBuf::new_p2pk(&PublicKey::new_uncompressed(pubkey)), None),
        2 => {
            let redeemscript = ScriptBuf::new_p2pkh(&PublicKey::new(pubkey).pubkey_hash());
            (redeemscript.clone(), Some(redeemscript.to_p2sh()))
        },
        3 => {
            let redeemscript = ScriptBuf::new_p2pkh(&PublicKey::new(pubkey).pubkey_hash());
            (redeemscript.clone(), Some(redeemscript.to_p2sh()))
        },
        4 => {
            let redeemscript = ScriptBuf::new_p2wpkh(&PublicKey::new(pubkey).wpubkey_hash().ok_or(Error::NoWitnessHash())?);
            (redeemscript.clone(), Some(redeemscript.to_p2sh()))
        },
        5 => (ScriptBuf::new_p2pkh(&PublicKey::new(pubkey).pubkey_hash()), None),
        6 => (ScriptBuf::new_p2pkh(&PublicKey::new_uncompressed(pubkey).pubkey_hash()), None),
        7 => {
            let redeemscript = ScriptBuf::new_p2pkh(&PublicKey::new(pubkey).pubkey_hash());
            (redeemscript.clone(), Some(redeemscript.to_p2wsh()))
        },
        8 => (ScriptBuf::new_p2wpkh(&PublicKey::new(pubkey).wpubkey_hash().ok_or(Error::NoWitnessHash())?), None),
        9 => (ScriptBuf::new_p2tr(ctx, sk.x_only_public_key(ctx).0, None), None),
        _ => return Err(Error::ValOutBounds())
    })
}

struct Utxo {
    key: SecretKey,
    redeem_script: Option<ScriptBuf>
}

fn do_test<R: io::Read + ?Sized>(r: &mut R) -> Result<(), Error> {
    let ctx = Secp256k1::<All>::new();
    let version = Version(i32::consensus_decode(r)?);
    let lock_time = u32::consensus_decode(r)?;

    let input_count = 1 + (u8::consensus_decode(r)? % 10) as usize;
    let output_count = 1 + (u8::consensus_decode(r)? % 10) as usize;

    let mut input: Vec<TxIn> = vec![];
    let mut cinputs: Vec<CompressedInput> = vec![];
    let mut utxos: Vec<Utxo> = vec![];
    let mut outs: Vec<(OutPoint, TxOut)> = vec![];

    let mut total = Amount::from_sat(0);

    while input.len() < input_count {
        let previous_output = OutPoint::new(Txid::consensus_decode(r)?, u32::consensus_decode(r)?);
        let sequence = Sequence::consensus_decode(r)?;
        let script_type = u8::consensus_decode(r)? % 10;
        let compressed_outpoint: bool = u8::consensus_decode(r)? % 2 > 0;
        let value = Amount::from_sat(max(output_count as u64, u64::consensus_decode(r)? % ((u64::MAX-total.to_sat()) / (input_count-input.len()) as u64)));
        if let Ok(sk) = SecretKey::from_slice(&<[u8; 32]>::consensus_decode(r)?) {
            total += value;
            let (script_pubkey, redeem_script) = get_script(script_type, sk, &ctx)?;
            utxos.push(Utxo{key: sk, redeem_script});
            outs.push((previous_output, TxOut{script_pubkey: script_pubkey.clone(), value}));
            cinputs.push(if compressed_outpoint {
                CompressedInput::new(CompressedOutPoint::new(u32::consensus_decode(r)?, u32::consensus_decode(r)?), script_pubkey)
            } else {
                CompressedInput::new_uncompressed(previous_output, script_pubkey)
            });
            input.push(TxIn{previous_output, script_sig: ScriptBuf::new(), sequence, witness: Witness::new()});
        }
    }

    let mut output: Vec<TxOut> = vec![];

    while output.len() < output_count {
        let script_type = u8::consensus_decode(r)? % 10;
        let value = Amount::from_sat(max(1, u64::consensus_decode(r)? % (total.to_sat()/(output_count-output.len()) as u64)));
        if let Ok(sk) = SecretKey::from_slice(&<[u8; 32]>::consensus_decode(r)?) {
            total -= value;
            let (script_pubkey, _) = get_script(script_type, sk, &ctx)?;
            output.push(TxOut{script_pubkey, value});
        }
    }

    let tx = Transaction{version, lock_time: LockTime::from_consensus(lock_time), input, output};

//  TODO: SIGN
//  let mut cache = SighashCache::new(&tx);
//  let sig_hash = cache.p2wpkh_signature_hash(i, script, out.value, EcdsaSighashType::from_consensus(hash_type as u32))?;
//  let message = &Message::from(sig_hash)
//  for (i, input) in tx.input.iter().enumerate().take(tx.input.len()) {
//      let script_pubkey = &outs[i].1.script_pubkey;
//      match ScriptType::from_script(script_pubkey) {
//          ScriptType::P2PK => {
//              let sighash = cache.legacy_signature_hash(i, script_pubkey, 0x01)?;
//              let message = &Message::from(sighash);
//              let signature = ctx.sign_ecdsa(message, &utxos[i].key);
//              tx.input[i].script_sig.push_slice(signature.serialize_der());
//              println!("ss: {}", hex::encode(tx.input[i].script_sig));
//              //let mut script_sig:  signature.serialize_der();
//              //script_sig.push(0x01);
//          },
//          _ => {}

//      }
//  }

    let minimum_height = if lock_time > 0 { lock_time-1 } else { 0 };

    let compressed_tx = CompressedTransaction::compress(&tx, minimum_height, &cinputs)?;
    let mut stream: Vec<u8> = vec![];
    compressed_tx.consensus_encode(&mut stream)?;
    let utx = CompressedTransaction::consensus_decode(&mut stream.as_slice())?;
    let new_tx = utx.decompress(&outs)?;
    assert!(tx == new_tx);


    Ok(())
}
