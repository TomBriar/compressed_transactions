use std::io;
use bitcoin::consensus::{Encodable, Decodable, WriteExt, ReadExt, encode};
use bitcoin::{ScriptBuf, PublicKey, ScriptHash, PubkeyHash, WScriptHash, WPubkeyHash, XOnlyPublicKey};
use secp256k1::{Secp256k1, All};
use bitcoin::hashes::Hash;
use crate::error::Error;

pub fn encode_varint<W: io::Write + ?Sized>(w: &mut W, val: u64) -> Result<usize, io::Error> {
    let mut tmp: Vec<u8> = vec![];
    let mut len: usize = 0;
    let mut n: u64 = val;
    loop {
        if len > 0 {
            tmp.push((n & 0x7F) as u8 | 0x80);
        } else {
            tmp.push((n & 0x7F) as u8);
        }
        len += 1;
        if n <= 0x7F { break; }
        n = (n >> 7) - 1;
    }

    for i in 0..len {
        tmp[len-i-1].consensus_encode(w)?;
    }
    Ok(len)
}
pub fn decode_varint<R: io::Read + ?Sized>(r: &mut R) -> Result<u64, encode::Error> {
    let mut n: u64 = 0;
    loop {
        let data: u8 = r.read_u8()?;
        if n > u64::MAX >> 7 {
            return Err(encode::Error::ParseFailed("ReadVarInt(): size too large"));
        }
        n = (n << 7) | (data & 0x7F) as u64;
        if (data & 0x80) > 0 {
            if n == u64::MAX {
                return Err(encode::Error::ParseFailed("ReadVarInt(): size too large"));
            }
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

pub fn encode_compact_size<W: io::Write + ?Sized>(w: &mut W, val: u64) -> Result<usize, io::Error> {
    match val {
        0..=0xFC => {
            (val as u8).consensus_encode(w)?;
            Ok(1)
        }
        0xFD..=0xFFFF => {
            w.emit_u8(0xFD)?;
            (val as u16).consensus_encode(w)?;
            Ok(3)
        }
        0x10000..=0xFFFFFFFF => {
            w.emit_u8(0xFE)?;
            (val as u32).consensus_encode(w)?;
            Ok(5)
        }
        _ => {
            w.emit_u8(0xFF)?;
            val.consensus_encode(w)?;
            Ok(9)
        }
    }
}

pub fn decode_compact_size<R: io::Read + ?Sized>(r: &mut R) -> Result<u64, encode::Error> {
    let n = ReadExt::read_u8(r)?;
    match n {
        0xFF => {
            Ok(ReadExt::read_u64(r)?)
        }
        0xFE => {
            Ok(ReadExt::read_u32(r)? as u64)
        }
        0xFD => {
            Ok(ReadExt::read_u16(r)? as u64)
        }
        n => Ok(n as u64),
    }
}

pub fn encode_bits<W: io::Write + ?Sized>(w: &mut W, data_vec: &[u64], bits_vec: &Vec<usize>) -> Result<usize, io::Error> {
    let mut len: usize = 0;

    let frombit = |i| {if i < bits_vec.len() { bits_vec[i] } else { bits_vec[bits_vec.len()-1] }};

    let mut acc: usize = 0;
    let mut acc_size: usize = 0;
    let max_acc = |i| { (1 << (frombit(i)+8-1)) -1 };

    for (i, v) in data_vec.iter().enumerate() {
        acc = ((acc << frombit(i)) | *v as usize) & max_acc(i);
        acc_size += frombit(i);
        while acc_size >= 8 {
            acc_size -= 8;
            len += (((acc >> acc_size) & u8::MAX as usize) as u8).consensus_encode(w)?;
        }
    }
    if acc_size > 0 { len += (((acc << (8 - acc_size)) & u8::MAX as usize) as u8).consensus_encode(w)?; }
    Ok(len)
}

pub fn decode_bits<R: io::Read + ?Sized>(r: &mut R, bits_vec: &Vec<usize>) -> Result<Vec<u64>, encode::Error> {
    if bits_vec.is_empty() { return Err(encode::Error::ParseFailed("decode_bits(): bits_vec must contain at least one value")); }
    let mut result: Vec<u64> = vec![];

    let mut acc: usize = 0;
    let mut acc_size: usize = 0;

    let max_acc = |tobit| { ((1_usize) << (8+tobit-1)) -1 };
    let maxv = |tobit| { ((1_usize) << tobit) - 1 };

    for tobit in bits_vec {
        while acc_size < *tobit {
            let v = u8::consensus_decode(r)?;
            acc = ((acc << 8) | v as usize) & max_acc(tobit);
            acc_size += 8;
        }
        acc_size -= tobit;
        result.push(((acc >> acc_size) & maxv(tobit)) as u64);
    }

    Ok(result)
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScriptType {
    NonStandard,
    P2PK,
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR
}

impl ScriptType {
    pub fn from_script(script: &ScriptBuf) -> ScriptType {
        match script {
            script if script.is_p2tr() => ScriptType::P2TR,
            script if script.is_p2wpkh() => ScriptType::P2WPKH,
            script if script.is_p2wsh() => ScriptType::P2WSH,
            script if script.is_p2pkh() => ScriptType::P2PKH,
            script if script.is_p2sh() => ScriptType::P2SH,
            script if script.is_p2pk() => ScriptType::P2PK,
            _ => ScriptType::NonStandard,
        }
    }
}

pub fn get_inner_bytes(script: &ScriptBuf) -> Vec<u8> {
    match ScriptType::from_script(script) {
        ScriptType::P2TR => script.to_bytes()[2..].to_vec(),
        ScriptType::P2WPKH => script.to_bytes()[2..].to_vec(),
        ScriptType::P2WSH => script.to_bytes()[2..].to_vec(),
        ScriptType::P2PKH => script.to_bytes()[3..23].to_vec(),
        ScriptType::P2SH => script.to_bytes()[2..22].to_vec(),
        ScriptType::P2PK if script.len() == 1+65+1 => script.to_bytes()[1..65+1].to_vec(),
        ScriptType::P2PK if script.len() == 1+33+1 => script.to_bytes()[1..33+1].to_vec(),
        _ => script.to_bytes()
    }
}

pub fn script_from_slice(script_type: &ScriptType, slice: &[u8]) -> Result<ScriptBuf, Error> {
    Ok(match script_type {
        ScriptType::P2PK => ScriptBuf::new_p2pk(&PublicKey::from_slice(slice)?),
        ScriptType::P2SH => ScriptBuf::new_p2sh(&ScriptHash::from_slice(slice)?),
        ScriptType::P2PKH => ScriptBuf::new_p2pkh(&PubkeyHash::from_slice(slice)?),
        ScriptType::P2WSH => ScriptBuf::new_p2wsh(&WScriptHash::from_slice(slice)?),
        ScriptType::P2WPKH => ScriptBuf::new_p2wpkh(&WPubkeyHash::from_slice(slice)?),
        ScriptType::P2TR => ScriptBuf::new_p2tr(&Secp256k1::<All>::new(), XOnlyPublicKey::from_slice(slice)?, None),
        _ => ScriptBuf::from_bytes(slice.to_vec())
    })
}
