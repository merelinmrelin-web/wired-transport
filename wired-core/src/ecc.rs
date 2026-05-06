use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

use crate::crypto;

const MAGIC: &[u8; 4] = b"WECC";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DEFAULT_SHARD_SIZE: usize = 192;
const MAX_SHARDS: usize = 255;

#[derive(Debug, Error)]
pub enum EccError {
    #[error("input is too large for the configured ECC layout")]
    InputTooLarge,
    #[error("invalid ECC packet")]
    InvalidPacket,
    #[error("not enough valid shards to reconstruct payload")]
    Unrecoverable,
    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
}

pub fn encode(payload: &[u8], recovery_rate: f32) -> Result<Vec<u8>, EccError> {
    let shard_size = DEFAULT_SHARD_SIZE;
    let data_shards = payload.len().max(1).div_ceil(shard_size);
    if data_shards >= MAX_SHARDS {
        return Err(EccError::InputTooLarge);
    }

    let parity_shards = parity_for_recovery(data_shards, recovery_rate);
    if data_shards + parity_shards > MAX_SHARDS {
        return Err(EccError::InputTooLarge);
    }

    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|err| EccError::ReedSolomon(err.to_string()))?;
    let mut shards = vec![vec![0u8; shard_size]; data_shards + parity_shards];

    for (idx, chunk) in payload.chunks(shard_size).enumerate() {
        shards[idx][..chunk.len()].copy_from_slice(chunk);
    }

    r.encode(&mut shards)
        .map_err(|err| EccError::ReedSolomon(err.to_string()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + shards.len() * (TAG_LEN + shard_size));
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(data_shards as u8);
    out.push(parity_shards as u8);
    out.push(0);
    out.extend_from_slice(&(shard_size as u16).to_be_bytes());
    out.extend_from_slice(&[0u8; 6]);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());

    for (idx, shard) in shards.iter().enumerate() {
        out.extend_from_slice(&shard_tag(idx, shard));
    }
    for shard in &shards {
        out.extend_from_slice(shard);
    }

    Ok(out)
}

pub fn decode(packet: &[u8]) -> Result<Vec<u8>, EccError> {
    if packet.len() < HEADER_LEN || &packet[..4] != MAGIC || packet[4] != VERSION {
        return Err(EccError::InvalidPacket);
    }

    let data_shards = packet[5] as usize;
    let parity_shards = packet[6] as usize;
    let shard_count = data_shards + parity_shards;
    let shard_size = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let payload_len = u64::from_be_bytes(packet[16..24].try_into().unwrap()) as usize;

    if data_shards == 0 || parity_shards == 0 || shard_size == 0 || shard_count > MAX_SHARDS {
        return Err(EccError::InvalidPacket);
    }

    let tag_bytes = shard_count * TAG_LEN;
    let shard_bytes = shard_count * shard_size;
    let expected_len = HEADER_LEN + tag_bytes + shard_bytes;
    if packet.len() != expected_len || payload_len > data_shards * shard_size {
        return Err(EccError::InvalidPacket);
    }

    let tags = &packet[HEADER_LEN..HEADER_LEN + tag_bytes];
    let shard_data = &packet[HEADER_LEN + tag_bytes..];
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(shard_count);

    for idx in 0..shard_count {
        let shard = &shard_data[idx * shard_size..(idx + 1) * shard_size];
        let expected_tag = &tags[idx * TAG_LEN..(idx + 1) * TAG_LEN];
        if shard_tag(idx, shard).as_slice() == expected_tag {
            shards.push(Some(shard.to_vec()));
        } else {
            shards.push(None);
        }
    }

    let valid = shards.iter().filter(|shard| shard.is_some()).count();
    if valid < data_shards {
        return Err(EccError::Unrecoverable);
    }

    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|err| EccError::ReedSolomon(err.to_string()))?;
    r.reconstruct(&mut shards)
        .map_err(|_| EccError::Unrecoverable)?;

    let mut out = Vec::with_capacity(data_shards * shard_size);
    for shard in shards.iter().take(data_shards) {
        let shard = shard.as_ref().ok_or(EccError::Unrecoverable)?;
        out.extend_from_slice(shard);
    }
    out.truncate(payload_len);
    Ok(out)
}

fn parity_for_recovery(data_shards: usize, recovery_rate: f32) -> usize {
    let rate = recovery_rate.clamp(0.05, 0.75);
    let parity = ((data_shards as f32 * rate) / (1.0 - rate)).ceil() as usize;
    parity.max(2)
}

fn shard_tag(idx: usize, shard: &[u8]) -> [u8; TAG_LEN] {
    let idx = (idx as u16).to_be_bytes();
    crypto::digest16(&[b"wired-transport shard v1", &idx, shard])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_corrupt_shards() {
        let payload = b"the quick brown fox jumps through a noisy transport".repeat(20);
        let packet = encode(&payload, 0.25).unwrap();

        let data_shards = packet[5] as usize;
        let parity_shards = packet[6] as usize;
        let shard_size = u16::from_be_bytes([packet[8], packet[9]]) as usize;
        let shard_count = data_shards + parity_shards;
        let data_offset = HEADER_LEN + shard_count * TAG_LEN;
        let mut damaged = packet;

        for shard_idx in 0..parity_shards {
            let pos = data_offset + shard_idx * shard_size;
            damaged[pos] ^= 0xff;
        }

        assert_eq!(decode(&damaged).unwrap(), payload);
    }
}
