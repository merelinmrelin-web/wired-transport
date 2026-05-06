# wired-transport

`wired-transport` is a Rust/WASM prototype for L7 steganography over valid PNG carriers. It encrypts payload bytes, applies Reed-Solomon forward error correction, and scatters the protected bitstream across RGB least-significant bits using deterministic pseudo-random mapping.

## Workspace

- `wired-core/`: reusable Rust library with `crypto`, `ecc`, and `stego_engine` modules.
- `wired-wasm/`: Leptos + Trunk browser UI with drag-and-drop PNG handling.

## Core API

```rust
use wired_core::{Decoder, Encoder};

let carrier = image::open("carrier.png")?;
let wired = Encoder::inject(carrier, b"payload", b"shared-key")?;
let recovered = Decoder::extract(wired, b"shared-key")?;
```

Use `Encoder::inject_with_config` to tune recovery overhead:

```rust
use wired_core::{Encoder, StegoConfig};

let config = StegoConfig {
    recovery_rate: 0.25,
    bit_repetition: 3,
};
```

## L7-Steganography Approach

1. Payload bytes are encrypted with `ring` ChaCha20-Poly1305 AEAD on native targets. The WASM target uses a pure-Rust ChaCha20-Poly1305/SHA-256 backend because `ring` requires a C toolchain path that is not consistently available for `wasm32-unknown-unknown` browser builds.
2. Encrypted bytes are packetized into fixed-size Reed-Solomon shards using `reed-solomon-erasure`.
3. Each shard receives a SHA-256-derived integrity tag so corrupted shards can be marked as erasures before reconstruction.
4. The ECC packet is converted to bits, repeated, and written into RGB LSB channels only.
5. `rand_xoshiro` maps bit positions from a key/salt-derived seed, scattering data across the image rather than creating a visible noisy block.
6. The result is saved as a normal PNG; headers and chunk structure are produced by the `image` crate and remain valid/viewable.

## Robustness Model

The default config uses `recovery_rate = 0.25` and `bit_repetition = 15`. Repetition absorbs random LSB flips at the bit level, while Reed-Solomon parity reconstructs shards that still fail integrity checks. This is intended to survive moderate random pixel/channel modification, including approximately 20% noisy pixel disturbance when the PNG dimensions and RGB samples are preserved.

This is not magic resistance to destructive transforms. JPEG conversion, aggressive palette quantization, resizing, cropping, or DPI workflows that resample pixels can destroy the exact LSB positions and the deterministic mapping. For hostile lossy pipelines, increase `bit_repetition`, use larger carrier images, and avoid transforms that change dimensions or rewrite color samples.

## Browser UI

The WASM app provides a dark terminal-style interface:

- Drag or select a PNG carrier.
- Enter a shared key and plaintext payload.
- Click `inject` to produce `wired-carrier.png`.
- Load a wired PNG and click `extract` with the same key.

Run locally:

```bash
cd wired-wasm
trunk serve
```

## Build Checks

```bash
cargo test -p wired-core
cargo check -p wired-wasm --target wasm32-unknown-unknown
```

If the WASM target is missing:

```bash
rustup target add wasm32-unknown-unknown
```
