use bitcoin::{Txid, TxIn, ScriptBuf, OutPoint, Transaction, TxOut, Amount, VarInt, Sequence, Witness};
use bitcoin::transaction::Version;
use bitcoin::absolute::{LockTime, Height};
use bitcoin::blockdata::opcodes::all::{OP_PUSHBYTES_65, OP_PUSHBYTES_33, OP_PUSHBYTES_32, OP_PUSHBYTES_20, OP_DUP, OP_HASH160, OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG};
use bitcoin::consensus::Encodable;
use crate::Error;
use std::io;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CompressedOutPoint {
    pub block_height: u32,
    pub block_index: u32,
}

impl CompressedOutPoint {
    pub fn new(block_height: u32, block_index: u32) -> Self {
        CompressedOutPoint {
            block_height: block_height, 
            block_index: block_index
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CompressedInput {
    pub compressed_outpoint: Option<CompressedOutPoint>,
    pub outpoint: Option<OutPoint>,
    pub script_pubkey: ScriptBuf 
}

impl CompressedInput {
    pub fn new(outpoint: OutPoint, script_pubkey: ScriptBuf) -> Self {
        CompressedInput {
            compressed_outpoint: None,
            outpoint: Some(outpoint),
            script_pubkey: script_pubkey
        }
    }

    pub fn new_compressed(compressed_outpoint: CompressedOutPoint, script_pubkey: ScriptBuf) -> Self {
        CompressedInput {
            compressed_outpoint: Some(compressed_outpoint),
            outpoint: None,
            script_pubkey: script_pubkey
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed_outpoint.is_some()
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CompressedTxIn {
    pub compressed_outpoint: Option<CompressedOutPoint>,
    pub outpoint: Option<OutPoint>,

    pub signature: Vec<u8>,
    pub pubkey_hash: Vec<u8>,

    pub hash_type: u8,
    pub is_hash_standard: bool,
    pub compressed_signature: bool,

    pub sequence: u32,
}

impl CompressedTxIn {
    pub fn outpoint_is_compressed(&self) -> bool{
        self.compressed_outpoint.is_some()
    }

    pub fn compress(txin: &TxIn, input: &CompressedInput) -> Result<Self, Error> {
        let compressed_outpoint: Option<CompressedOutPoint> = input.compressed_outpoint.clone();
        let outpoint: Option<OutPoint> = input.outpoint.clone();

        let mut signature: Vec<u8> = vec![];
        let mut pubkey_hash: Vec<u8> = vec![];
        
        let mut hash_type: u8 = 0;
        let mut is_hash_standard: bool = true;
        let mut compressed_signature: bool = false;
        
        if txin.script_sig.len() > 0 || !txin.witness.is_empty() {
            match &input.script_pubkey {
                script if script.is_p2tr() => {
                    let stack = txin.witness.to_vec();
                    if stack.len() == 1 && (stack[0].len() == 64 || stack[0].len() == 65) {
                        signature = stack[0].clone();
                        if signature.len() == 65 {
                            hash_type = signature.pop().unwrap();
                            is_hash_standard = hash_type == 0x00;
                        }
                        compressed_signature = true;
                    }
                },
                _ => {}
            }


            if !compressed_signature {
                VarInt::from(txin.script_sig.len() as u64).consensus_encode(&mut signature)?;
                if !txin.script_sig.is_empty() {
                    signature.append(&mut txin.script_sig.to_bytes());
                }
                let stack = txin.witness.to_vec();
                VarInt::from(stack.len() as u64).consensus_encode(&mut signature)?;
                for mut item in stack {
                    VarInt::from(item.len() as u64).consensus_encode(&mut signature)?;
                    signature.append(&mut item);
                }
            }
        }

        let sequence: u32 = txin.sequence.to_consensus_u32();
        
        Ok(CompressedTxIn{ 
            compressed_outpoint: compressed_outpoint, 
            outpoint: outpoint, 
            signature: signature, 
            pubkey_hash: pubkey_hash, 
            hash_type: hash_type, 
            is_hash_standard: is_hash_standard, 
            compressed_signature: compressed_signature,
            sequence: sequence
        })
    }
}

#[derive(Debug, Clone)]
pub enum ScriptType {
    P2PK = 1,
    P2PKH = 2,
    P2SH = 3,
    P2WPKH = 4,
    P2WSH = 5,
    P2TR = 6,
    NONSTANDARD = 0
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CompressedTxOut {
    pub script_type: ScriptType,
    pub script_pubkey: Vec<u8>,
    pub value: u64
}

impl CompressedTxOut{
    pub fn compress(txout: &TxOut) -> Self {
        let mut script_type: ScriptType = ScriptType::NONSTANDARD;
        let mut script_pubkey: Vec<u8> = Vec::new();
        let value: u64 = txout.value.to_sat();
        println!("{}", txout.script_pubkey.is_p2wpkh());
        match &txout.script_pubkey {
            script if script.is_p2tr() => { script_pubkey = script.to_bytes()[2..].to_vec(); script_type = ScriptType::P2TR; }
            script if script.is_p2wpkh() => { script_pubkey = script.to_bytes()[2..].to_vec(); script_type = ScriptType::P2WPKH; }
            script if script.is_p2wsh() => { script_pubkey = script.to_bytes()[2..].to_vec(); script_type = ScriptType::P2WSH; }
            script if script.is_p2pkh() => { script_pubkey = script.to_bytes()[3..23].to_vec(); script_type = ScriptType::P2PKH; }
            script if script.is_p2sh() => { script_pubkey = script.to_bytes()[2..22].to_vec(); script_type = ScriptType::P2SH; }
            script if script.is_p2pk() && script.len() == 1+65+1 => { script_pubkey = script.to_bytes()[1..65+1].to_vec(); script_type = ScriptType::P2PK; }
            script if script.is_p2pk() && script.len() == 1+33+1 => { script_pubkey = script.to_bytes()[1..33+1].to_vec(); script_type = ScriptType::P2PK; }
            script => { script_pubkey = script.to_bytes(); }
        }
        CompressedTxOut{
            script_type: script_type,
            script_pubkey: script_pubkey,
            value: value
        }
    }

    pub fn decompress(ctxout: &CompressedTxOut) -> TxOut {
        let value: Amount = Amount::from_sat(ctxout.value);
        let script_pubkey: ScriptBuf = ScriptBuf::from_bytes(match ctxout.script_type {
            ScriptType::P2TR => [[0x51, OP_PUSHBYTES_32.to_u8()].to_vec(), ctxout.script_pubkey.clone()].concat(),
            ScriptType::P2WPKH => [[0x00, OP_PUSHBYTES_20.to_u8()].to_vec(), ctxout.script_pubkey.clone()].concat(),
            ScriptType::P2WSH => [[0x00, OP_PUSHBYTES_32.to_u8()].to_vec(), ctxout.script_pubkey.clone()].concat(),
            ScriptType::P2PKH => [[vec![OP_DUP.to_u8(), OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()], ctxout.script_pubkey.clone()].concat(), vec![OP_EQUALVERIFY.to_u8(), OP_CHECKSIG.to_u8()]].concat(),
            ScriptType::P2SH => [[vec![OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()], ctxout.script_pubkey.clone()].concat(), vec![OP_EQUAL.to_u8()]].concat(),
            ScriptType::P2PK if ctxout.script_pubkey.len() == 65 => [[vec![OP_PUSHBYTES_65.to_u8()], ctxout.script_pubkey.clone()].concat(), vec![OP_CHECKSIG.to_u8()]].concat(),
            ScriptType::P2PK if ctxout.script_pubkey.len() == 33 => [[vec![OP_PUSHBYTES_33.to_u8()], ctxout.script_pubkey.clone()].concat(), vec![OP_CHECKSIG.to_u8()]].concat(),
            _ => ctxout.script_pubkey.clone()
        });
        
        TxOut{
            script_pubkey: script_pubkey,
            value: value
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CompressedTransaction {
    pub minimum_height: u32,

    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<CompressedTxIn>,
    pub output: Vec<CompressedTxOut>
}

impl CompressedTransaction {
    pub fn compress(tx: &Transaction, minimum_height: u32, cinputs: &Vec<CompressedInput>) -> Result<Self, Error> {
        let version: i32 = tx.version.0;

        let mut lock_time: u32 = tx.lock_time.to_consensus_u32();
        if lock_time > 0 { lock_time -= minimum_height }

        let mut input: Vec<CompressedTxIn> = vec![];
        for i in 0..tx.input.len() {
            input.push(CompressedTxIn::compress(&tx.input[i], &cinputs[i])?);
        }

        let mut output: Vec<CompressedTxOut> = vec![];
        for txout in &tx.output {
            output.push(CompressedTxOut::compress(txout));
        }
        
        Ok(CompressedTransaction{ minimum_height: minimum_height, version: version, lock_time: lock_time, input: input, output: output})
    }

    pub fn decompress(ctx: &CompressedTransaction, prevouts: &Vec<OutPoint>, outs: &Vec<TxOut>) -> Result<Transaction, Error> {
        let version: Version = Version(ctx.version);
        let mut lock_time_u32: u32 = 0;
        if ctx.lock_time > 0 {lock_time_u32 += ctx.minimum_height;}
        let mut lock_time: LockTime = LockTime::Blocks(Height::from_consensus(lock_time_u32)?);

        let mut output: Vec<TxOut> = vec![];
        for txout in &ctx.output {
            output.push(CompressedTxOut::decompress(txout));
        }

        let mut input: Vec<TxIn> = vec![];
        for i in 0..ctx.input.len() {
            let mut script_sig: ScriptBuf = ScriptBuf::new();
            let mut witness: Witness = Witness::new();



            let ctxin = &ctx.input[i];
            let prevout = &prevouts[i];
            let out = &outs[i];


            if ctxin.compressed_signature {
                if out.script_pubkey.is_p2tr() {
                    if ctxin.is_hash_standard { 
                        witness.push(ctxin.signature.clone());
                    } else { 
                        witness.push([ctxin.signature.clone(), vec![ctxin.hash_type]].concat());
                    }
                }
            }

            input.push(TxIn{previous_output: *prevout, script_sig: script_sig, sequence: Sequence::from_consensus(ctxin.sequence), witness: witness});
        }
       
        Ok(Transaction{version: version, lock_time: lock_time, input: input, output: output})
    }
}

impl Encodable for CompressedTransaction {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len: usize = 0;

        let mut control: u8 = 0;
        if self.version      < 4 && self.version      > 0 { control = self.version as u8 }
        if self.input.len()  < 4 && self.input.len()  > 0 { control |= (self.input.len() as u8) << 2 }
        if self.output.len() < 4 && self.output.len() > 0 { control |= (self.output.len() as u8) << 4 }
        if self.lock_time > 0 { control |= 0b01000000 }
        len += VarInt::from(control).consensus_encode(w)?;

        if (control & 0x03) == 0 { len += VarInt::from(self.version as u64).consensus_encode(w)? }
        if (control & 0x0c) == 0 { len += VarInt::from(self.input.len()).consensus_encode(w)? }
        if (control & 0x30) == 0 { len += VarInt::from(self.output.len()).consensus_encode(w)? }
        if (control & 0xc0) >  0 { len += VarInt::from(self.lock_time).consensus_encode(w)? }

        let mut test: Vec<u8> = vec![];
        VarInt::from(self.minimum_height).consensus_encode(&mut test)?;
        println!("mini: {}", self.minimum_height);
        println!("var: {}", hex::encode(test));

        len += VarInt::from(self.minimum_height).consensus_encode(w)?;

//      // Legacy transaction serialization format only includes inputs and outputs.
//      if !self.use_segwit_serialization() {
//          len += self.input.consensus_encode(w)?;
//          len += self.output.consensus_encode(w)?;
//      } else {
//          // BIP-141 (segwit) transaction serialization also includes marker, flag, and witness data.
//          len += SEGWIT_MARKER.consensus_encode(w)?;
//          len += SEGWIT_FLAG.consensus_encode(w)?;
//          len += self.input.consensus_encode(w)?;
//          len += self.output.consensus_encode(w)?;
//          for input in &self.input {
//              len += input.witness.consensus_encode(w)?;
//          }
//      }
//      len += self.lock_time.consensus_encode(w)?;
        Ok(len)
    }
}
