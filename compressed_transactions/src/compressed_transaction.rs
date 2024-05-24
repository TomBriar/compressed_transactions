use crate::util::{encode_varint, decode_varint, encode_compact_size, decode_compact_size, encode_bits, decode_bits, ScriptType, get_inner_bytes, script_from_slice};
use crate::error::Error;
use bitcoin::{TxIn, ScriptBuf, OutPoint, Transaction, TxOut, Amount, Sequence, Witness, WPubkeyHash, PubkeyHash, EcdsaSighashType};
use bitcoin::consensus::{Decodable, Encodable, encode};
use bitcoin::absolute::{LockTime, Height};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::hashes::Hash;
use secp256k1::ecdsa::{RecoveryId, RecoverableSignature, Signature};
use secp256k1::Message;
use std::io;

#[derive(Debug, Clone, PartialEq)]
pub struct CompressedOutPoint {
    block_height: u32,
    block_index: u32,
}

impl CompressedOutPoint {
    pub fn block_height(&self) -> u32 {self.block_height}
    pub fn block_index(&self) -> u32 {self.block_index}

    pub fn new(block_height: u32, block_index: u32) -> Self {
        CompressedOutPoint{block_height, block_index}
    }
}

impl Encodable for CompressedOutPoint {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = encode_varint(w, self.block_height as u64)?;
        Ok(len + encode_varint(w, self.block_index as u64)?)
    }
}

impl Decodable for CompressedOutPoint{
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(CompressedOutPoint::new(decode_varint(r)? as u32, decode_varint(r)? as u32))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompressedInput {
    compressed_outpoint: Option<CompressedOutPoint>,
    outpoint: Option<OutPoint>,
    script_pubkey: ScriptBuf
}

impl CompressedInput {
    pub fn compressed_outpoint(&self) -> &Option<CompressedOutPoint>{&self.compressed_outpoint}
    pub fn outpoint(&self) -> &Option<OutPoint> {&self.outpoint}
    pub fn script_pubkey(&self) -> &ScriptBuf {&self.script_pubkey}

    pub fn new_uncompressed(outpoint: OutPoint, script_pubkey: ScriptBuf) -> Self {
        CompressedInput{compressed_outpoint: None, outpoint: Some(outpoint), script_pubkey}
    }

    pub fn new(compressed_outpoint: CompressedOutPoint, script_pubkey: ScriptBuf) -> Self {
        CompressedInput {
            compressed_outpoint: Some(compressed_outpoint),
            outpoint: None,
            script_pubkey
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompressedTxIn {
    compressed_outpoint: Option<CompressedOutPoint>,
    outpoint: Option<OutPoint>,
    signature: Vec<u8>,
    pubkey_hash: Vec<u8>,
    hash_type: u8,
    is_hash_standard: bool,
    compressed_signature: bool,
    sequence: u32,
}

impl CompressedTxIn {
    pub fn compressed_outpoint(&self) -> &Option<CompressedOutPoint>{&self.compressed_outpoint}
    pub fn outpoint(&self) -> &Option<OutPoint> {&self.outpoint}
    pub fn signature(&self) -> &Vec<u8> {&self.signature}
    pub fn pubkey_hash(&self) -> &Vec<u8> {&self.pubkey_hash}
    pub fn hash_type(&self) -> u8 {self.hash_type}
    pub fn is_hash_standard(&self) -> bool {self.is_hash_standard}
    pub fn compressed_signature(&self) -> bool {self.compressed_signature}
    pub fn sequence(&self) -> u32 {self.sequence}

    pub const METADATA_SIZE: usize = 6;

    pub fn metadata(&self) -> u8 {
        let sequence: u8 = match self.sequence {
            0x00000000 => 1,
            0xFFFFFFFE => 2,
            0xFFFFFFFF => 3,
            _ => 0
        };

        let mut result: u8 = 0;
        result |= self.compressed_signature as u8;
        result |= (!self.pubkey_hash.is_empty() as u8) << 1;
        result |= (self.is_hash_standard as u8) << 2;
        result |= sequence << 3;
        result |= (self.compressed_outpoint.is_some() as u8) << 5;
        result
    }

    pub fn is_sequence_standard(&self) -> bool {
        self.sequence == 0x00000000 || self.sequence == 0xFFFFFFFE || self.sequence == 0xFFFFFFFF
    }

    pub fn compress(txin: &TxIn, input: &CompressedInput) -> Result<Self, Error> {
        let compressed_outpoint: Option<CompressedOutPoint> = input.compressed_outpoint.clone();
        let outpoint: Option<OutPoint> = input.outpoint;
        let sequence: u32 = txin.sequence.to_consensus_u32();

        if txin.script_sig.len() > 0 || !txin.witness.is_empty() {
            let stack = txin.witness.to_vec();
            //Try to parse script_sig and witness for compression
            if let Ok((signature, pubkey_hash, hash_type, is_hash_standard)) = match &input.script_pubkey {
                script if script.is_p2tr() && stack.len() == 1 && (stack[0].len() == 64 || stack[0].len() == 65) => {
                    let hash_type: u8 = if stack[0].len() == 65 { stack[0][64] } else { 0 };
                    Ok((stack[0][..64].to_vec(), vec![], hash_type, hash_type == 0x00))
                },
                script if script.is_p2wpkh() && stack.len() == 2 && stack[0].len() == 71 => {
                    let hash_type: u8 = if stack[0][70] != 0x01 { stack[0][70] } else { 0 };
                    Ok((Signature::from_der(&stack[0][..70])?.serialize_compact().to_vec(), vec![], hash_type, stack[0][70] == 0x01))
                },
                script if script.is_p2sh() && txin.script_sig.len() > 0 => {
                    let redeem_script: ScriptBuf = ScriptBuf::from_bytes(txin.script_sig.to_bytes()[1..].to_vec());
                    if redeem_script.is_p2wpkh() && stack.len() == 2 && stack[0].len() == 71 {
                        let hash_type: u8 = if stack[0][70] != 0x01 { stack[0][70] } else { 0 };
                        Ok((Signature::from_der(&stack[0][..70])?.serialize_compact().to_vec(), get_inner_bytes(&redeem_script), hash_type, stack[0][70] == 0x01))
                    } else {
                        Err(Error::CannotCompress())
                    }
                },
                script if script.is_p2pkh() && txin.script_sig.len() >= 72 => {
                    let ht: u8 = txin.script_sig.to_bytes()[71];
                    let hash_type: u8 = if ht != 0x01 { ht } else { 0 };
                    Ok((Signature::from_der(&txin.script_sig.to_bytes()[1..71])?.serialize_compact().to_vec(), vec![], hash_type, ht == 0x01))
                },
                _ => {Err(Error::CannotCompress())}
            } { return Ok(CompressedTxIn{compressed_outpoint, outpoint, signature, pubkey_hash, hash_type, is_hash_standard, compressed_signature: true, sequence}) }

            //Serialize both the script_sig and witness if compression failed above
            let mut signature: Vec<u8> = vec![];
            txin.script_sig.consensus_encode(&mut signature)?;
            txin.witness.consensus_encode(&mut signature)?;
            return Ok(CompressedTxIn{compressed_outpoint, outpoint, signature, pubkey_hash: vec![], hash_type: 0, is_hash_standard: false, compressed_signature: false, sequence})
        }
        // If script_sig and witness are both empty ignore completely
        Ok(CompressedTxIn{compressed_outpoint, outpoint, signature: vec![], pubkey_hash: vec![], hash_type: 0, is_hash_standard: false, compressed_signature: false, sequence})
    }

    pub fn consensus_decode<R: io::Read + ?Sized>(r: &mut R, m: u8) -> Result<Self, encode::Error> {
        let compressed_signature: bool =    (m & 0b00000001)       > 0;
        let pubkey_hash_present: bool =    ((m & 0b00000010) >> 1) > 0;
        let is_hash_standard: bool =       ((m & 0b00000100) >> 2) > 0;
        let sequence_encoding: u8 =         (m & 0b00011000) >> 3;
        let is_outpoint_compressed: bool = ((m & 0b00100000) >> 5) > 0;

        let (compressed_outpoint, outpoint) = if is_outpoint_compressed {
            (Some(CompressedOutPoint::consensus_decode(r)?), None)
        } else {
            (None, Some(OutPoint::consensus_decode(r)?))
        };

        let mut signature: Vec<u8> = vec![];
        let mut pubkey_hash: Vec<u8> = vec![];
        let mut hash_type: u8 = 0;

        if compressed_signature {
            for _ in 0..64 {
                signature.push(u8::consensus_decode(r)?);
            }
            if pubkey_hash_present {
                for _ in 0..20 {
                    pubkey_hash.push(u8::consensus_decode(r)?);
                }
            }
            if !is_hash_standard {
                hash_type = u8::consensus_decode(r)?;
            }
        } else {
            signature = Vec::<u8>::consensus_decode(r)?;
        }

        let sequence = match sequence_encoding {
            1 => 0x00000000,
            2 => 0xFFFFFFFE,
            3 => 0xFFFFFFFF,
            _ => decode_varint(r)? as u32
        };

        Ok(CompressedTxIn{compressed_outpoint, outpoint, signature, pubkey_hash, hash_type, is_hash_standard, compressed_signature, sequence})
    }
}

impl Encodable for CompressedTxIn {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len: usize = 0;
        if self.compressed_outpoint.is_some() {
            len += self.compressed_outpoint.as_ref().unwrap().consensus_encode(w)?;
        } else {
            len += self.outpoint.as_ref().unwrap().consensus_encode(w)?;
        }

        if self.compressed_signature {
            for c in &self.signature {
                len += c.consensus_encode(w)?;
            }
            if !self.pubkey_hash.is_empty() {
                for c in &self.pubkey_hash {
                    len += c.consensus_encode(w)?;
                }
            }
            if !self.is_hash_standard {
                len += self.hash_type.consensus_encode(w)?;
            }
        } else {
            len += self.signature.consensus_encode(w)?;
        }

        if !self.is_sequence_standard() {
            len += encode_varint(w, self.sequence as u64)?;
        }
        Ok(len)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CompressedTxOut {
    script_type: ScriptType,
    script_pubkey: Vec<u8>,
    value: u64
}

impl CompressedTxOut{
    pub fn script_type(&self) -> &ScriptType {&self.script_type}
    pub fn script_pubkey(&self) -> &Vec<u8> {&self.script_pubkey}
    pub fn value(&self) -> u64 {self.value}

    pub const METADATA_SIZE: usize = 3;

    pub fn metadata(&self) -> u8 {
        match self.script_type {
            ScriptType::P2PK if self.script_pubkey.len() == 65 => 1,
            ScriptType::P2PK if self.script_pubkey.len() == 33 => 2,
            ScriptType::P2PKH => 3,
            ScriptType::P2SH => 4,
            ScriptType::P2WPKH => 5,
            ScriptType::P2WSH => 6,
            ScriptType::P2TR => 7,
            _ => 0
        }
    }

    pub fn compress(txout: &TxOut) -> Self {
        CompressedTxOut{
            script_type: ScriptType::from_script(&txout.script_pubkey),
            script_pubkey: get_inner_bytes(&txout.script_pubkey),
            value: txout.value.to_sat()
        }
    }

    pub fn decompress(ctxout: &CompressedTxOut) -> Result<TxOut, Error> {
        Ok(TxOut{
            script_pubkey: script_from_slice(&ctxout.script_type, &ctxout.script_pubkey)?,
            value: Amount::from_sat(ctxout.value)
        })
    }

    pub fn consensus_decode<R: io::Read + ?Sized>(r: &mut R, m: u8) -> Result<Self, encode::Error> {
        let mut script_pubkey: Vec<u8> = vec![];
        let (script_length, script_type) = match m {
            1 => (65, ScriptType::P2PK),
            2 => (33, ScriptType::P2PK),
            3 => (20, ScriptType::P2PKH),
            4 => (20, ScriptType::P2SH),
            5 => (20, ScriptType::P2WPKH),
            6 => (32, ScriptType::P2WSH),
            7 => (32, ScriptType::P2TR),
            _ => (0, ScriptType::NonStandard),
        };

        if script_length > 0 {
            for _ in 0..script_length {
                script_pubkey.push(u8::consensus_decode(r)?);
            }
        } else {
            script_pubkey = Vec::<u8>::consensus_decode(r)?;
        }

        Ok(CompressedTxOut{script_type, script_pubkey, value: decode_varint(r)?})
    }
}

impl Encodable for CompressedTxOut {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len: usize = 0;
        if self.metadata() > 0 {
            for c in &self.script_pubkey {
                len += c.consensus_encode(w)?;
            }
        } else {
            len += self.script_pubkey.consensus_encode(w)?;
        }
        Ok(len + encode_varint(w, self.value)?)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CompressedTransaction {
    minimum_height: u32,
    version: i32,
    lock_time: u32,
    input: Vec<CompressedTxIn>,
    output: Vec<CompressedTxOut>
}

impl CompressedTransaction {
    pub fn minimum_height(&self) -> u32 {self.minimum_height}
    pub fn version(&self) -> i32 {self.version}
    pub fn lock_time(&self) -> u32 {self.lock_time}
    pub fn input(&self) -> &Vec<CompressedTxIn> {&self.input}
    pub fn output(&self) -> &Vec<CompressedTxOut> {&self.output}

    pub fn compress(tx: &Transaction, minimum_height: u32, cinputs: &[CompressedInput]) -> Result<Self, Error> {
        let version: i32 = tx.version.0;

        let mut lock_time: u32 = tx.lock_time.to_consensus_u32();
        if lock_time > 0 { lock_time -= minimum_height }

        let mut input: Vec<CompressedTxIn> = vec![];
        for (i, cinput) in cinputs.iter().enumerate().take(tx.input.len()) {
            input.push(CompressedTxIn::compress(&tx.input[i], cinput)?);
        }

        let mut output: Vec<CompressedTxOut> = vec![];
        for txout in &tx.output {
            output.push(CompressedTxOut::compress(txout));
        }

        Ok(CompressedTransaction{ minimum_height, version, lock_time, input, output})
    }

    pub fn decompress(&self, preouts: &[(OutPoint, TxOut)]) -> Result<Transaction, Error> {
        let version: Version = Version(self.version);
        let mut lock_time_u32: u32 = 0;
        if self.lock_time > 0 {lock_time_u32 += self.minimum_height;}
        let lock_time: LockTime = LockTime::Blocks(Height::from_consensus(lock_time_u32)?);

        let mut output: Vec<TxOut> = vec![];
        for txout in &self.output {
            output.push(CompressedTxOut::decompress(txout)?);
        }

        let mut result: Transaction = Transaction{version, lock_time, output, input: vec![]};

        for (i, (prevout, _)) in preouts.iter().enumerate().take(self.input.len()) {
            result.input.push(TxIn{previous_output: *prevout, script_sig: ScriptBuf::new(), sequence: Sequence(self.input[i].sequence), witness: Witness::new()});
        }
        for (i, (_, out)) in preouts.iter().enumerate().take(self.input.len()) {
            let ctxin = &self.input[i];

            if ctxin.compressed_signature {
                match &out.script_pubkey {
                    script if script.is_p2tr() => {
                        if ctxin.is_hash_standard {
                            result.input[i].witness.push(ctxin.signature.clone());
                        } else {
                            result.input[i].witness.push([ctxin.signature.clone(), vec![ctxin.hash_type]].concat());
                        }
                    },
                    script if script.is_p2wpkh() => {
                        let hash_type = if ctxin.is_hash_standard { 0x01 } else { ctxin.hash_type };
                        let mut cache = SighashCache::new(&result);
                        let sig_hash = cache.p2wpkh_signature_hash(i, script, out.value, EcdsaSighashType::from_consensus(hash_type as u32))?;
                        for rec_id in 0..4 {
                            let rec_signature = RecoverableSignature::from_compact(&ctxin.signature, RecoveryId::from_i32(rec_id)?)?;
                            let public_key = match rec_signature.recover(&Message::from(sig_hash)) {
                                Ok(pk) => pk,
                                Err(_) => continue
                            };
                            if script != &ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&public_key.serialize())) { continue; }
                            result.input[i].witness.push([Signature::from_compact(&ctxin.signature)?.serialize_der().to_vec(), vec![hash_type]].concat());
                            result.input[i].witness.push(public_key.serialize());
                        }
                    },
                    script if script.is_p2sh() => {
                        let hash_type = if ctxin.is_hash_standard { 0x01 } else { ctxin.hash_type };
                        let mut cache = SighashCache::new(&result);
                        let script_code = script_from_slice(&ScriptType::P2WPKH, &ctxin.pubkey_hash)?;
                        let sig_hash = cache.p2wpkh_signature_hash(i, &script_code, out.value, EcdsaSighashType::from_consensus(hash_type as u32))?;
                        for rec_id in 0..4 {
                            let rec_signature = RecoverableSignature::from_compact(&ctxin.signature, RecoveryId::from_i32(rec_id)?)?;
                            let public_key = match rec_signature.recover(&Message::from(sig_hash)) {
                                Ok(pk) => pk,
                                Err(_) => continue
                            };
                            if script_code != ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&public_key.serialize())) { continue; }
                            result.input[i].script_sig = ScriptBuf::from_bytes([vec![22], script_code.as_bytes().to_vec()].concat());
                            result.input[i].witness.push([Signature::from_compact(&ctxin.signature)?.serialize_der().to_vec(), vec![hash_type]].concat());
                            result.input[i].witness.push(public_key.serialize());
                        }

                    },
                    script if script.is_p2pkh() => {
                        let hash_type = if ctxin.is_hash_standard { 0x01 } else { ctxin.hash_type };
                        let cache = SighashCache::new(&result);
                        let sig_hash = cache.legacy_signature_hash(i, script, hash_type as u32)?;
                        for rec_id in 0..4 {
                            let rec_signature = RecoverableSignature::from_compact(&ctxin.signature, RecoveryId::from_i32(rec_id)?)?;
                            let public_key = match rec_signature.recover(&Message::from(sig_hash)) {
                                Ok(pk) => pk,
                                Err(_) => continue
                            };
                            let pubkey_ser = match script {
                                script if script == &ScriptBuf::new_p2pkh(&PubkeyHash::hash(&public_key.serialize_uncompressed())) => public_key.serialize_uncompressed().to_vec(),
                                script if script == &ScriptBuf::new_p2pkh(&PubkeyHash::hash(&public_key.serialize())) => public_key.serialize().to_vec(),
                                _ => continue
                            };
                            result.input[i].script_sig = ScriptBuf::from_bytes(vec![vec![0x47], Signature::from_compact(&ctxin.signature)?.serialize_der().to_vec(), vec![hash_type, pubkey_ser.len() as u8], pubkey_ser].into_iter().flatten().collect());
                        }
                    },
                    _ => {}
                }
            } else {
                let mut signature = ctxin.signature.as_slice();
                result.input[i].script_sig = ScriptBuf::consensus_decode(&mut signature)?;
                result.input[i].witness = Witness::consensus_decode(&mut signature)?;
            }
        }
        Ok(result)
    }
}

impl Encodable for CompressedTransaction {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len: usize = 0;

        let mut control: u8 = 0;
        if self.version      < 4 && self.version > 0 { control = self.version as u8 }
        if self.input.len()  < 4 && !self.input.is_empty() { control |= (self.input.len() as u8) << 2 }
        if self.output.len() < 4 && !self.output.is_empty() { control |= (self.output.len() as u8) << 4 }
        if self.lock_time > 0      { control |= 0b01000000 }
        if self.minimum_height > 0 { control |= 0b10000000 }
        len += control.consensus_encode(w)?;

        if (control & 0b00000011) == 0 { len += encode_compact_size(w, self.version as u64)?; }
        if (control & 0b00001100) == 0 { len += encode_compact_size(w, self.input.len() as u64)?; }
        if (control & 0b00110000) == 0 { len += encode_compact_size(w, self.output.len() as u64)?; }
        if (control & 0b01000000) >  0 { len += encode_compact_size(w, self.lock_time as u64)?; }
        if (control & 0b10000000) >  0 { len += encode_varint(w, self.minimum_height as u64)?; }

        let mut metadata: Vec<u64> = vec![];
        let mut metadata_size: Vec<usize> = vec![];

        for txin in &self.input {
            metadata.push(txin.metadata() as u64);
            metadata_size.push(CompressedTxIn::METADATA_SIZE);
        }
        for txout in &self.output {
            metadata.push(txout.metadata() as u64);
            metadata_size.push(CompressedTxOut::METADATA_SIZE);
        }
        len += encode_bits(w, &metadata, &metadata_size)?;

        for txin in &self.input {
            len += txin.consensus_encode(w)?;
        }

        for txout in &self.output {
            len += txout.consensus_encode(w)?;
        }

        Ok(len)
    }
}

impl Decodable for CompressedTransaction {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let control: u8 = u8::consensus_decode(r)?;

        let version: i32        = if (control & 0b00000011) == 0 { decode_compact_size(r)? as i32 } else {    (control & 0b00000011) as i32 };
        let input_count: usize  = if (control & 0b00001100) == 0 { decode_compact_size(r)? as usize } else { ((control & 0b00001100) >> 2) as usize };
        let output_count: usize = if (control & 0b00110000) == 0 { decode_compact_size(r)? as usize } else { ((control & 0b00110000) >> 4) as usize };
        let lock_time: u32      = if (control & 0b01000000) >  0 { decode_compact_size(r)? as u32 } else { 0 };
        let minimum_height: u32 = if (control & 0b10000000) >  0 { decode_varint(r)? as u32 } else { 0 };

        let mut metadata_size: Vec<usize> = vec![];

        for _ in 0..input_count {
            metadata_size.push(CompressedTxIn::METADATA_SIZE);
        }
        for _ in 0..output_count {
            metadata_size.push(CompressedTxOut::METADATA_SIZE);
        }

        let metadata: Vec<u64> = decode_bits(r, &metadata_size)?;

        let mut input: Vec<CompressedTxIn> = vec![];
        for m in metadata.iter().take(input_count) {
            input.push(CompressedTxIn::consensus_decode(r, *m as u8)?);
        }

        let mut output: Vec<CompressedTxOut> = vec![];
        for i in 0..output_count {
            let m = metadata[input_count+i];
            output.push(CompressedTxOut::consensus_decode(r, m as u8)?);
        }

        Ok(CompressedTransaction{version, input, output, lock_time, minimum_height})
    }
}
