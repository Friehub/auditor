# Crate: `frensense-frc` — Binary Bundle Format

**Path:** `frensense-frc/src/lib.rs`  
**Role:** Leaf crate. Defines the `.frc` on-disk format envelope. No analysis logic — pure serialization/deserialization.

---

## Purpose

The `.frc` (Frensense Reference Corpus) file is the pre-compiled binary artifact that the scanner loads at startup. It contains all corpus pattern fingerprints, learned weights, calibration parameters, and semantic filters in one signed binary blob. Keeping the format in its own crate ensures that both the bundler (writer) and the engine (reader) share the exact same format definition with no divergence.

---

## On-Disk Format

```
Offset  Size              Field
──────  ────────────────  ─────────────────────────────────────────────
0       4 bytes (LE u32)  header_len: length of the serialized header
4       header_len        BundleHeader (bincode-serialized)
4+n     remaining bytes   BundlePayload (bincode-serialized)
```

### `BundleHeader`

```rust
pub struct BundleHeader {
    pub magic:         [u8; 4],  // Always b"FRC1"
    pub version:       u32,      // Currently 4
    pub pattern_count: u32,      // Number of patterns in the payload
    pub checksum:      [u8; 32], // BLAKE3 hash of the payload bytes
}
```

### Constants

```rust
pub const BUNDLE_MAGIC:   &[u8; 4] = b"FRC1";
pub const BUNDLE_VERSION: u32      = 4;
```

---

## API

### `write_bundle<T: Serialize>`

```rust
pub fn write_bundle<T: serde::Serialize>(
    payload: &T,
    pattern_count: u32,
) -> Result<Vec<u8>, String>
```

1. Serializes `payload` to bytes via `bincode`.
2. Computes `BLAKE3(payload_bytes)` — a 32-byte cryptographic hash.
3. Builds `BundleHeader` with the hash.
4. Serializes the header via `bincode`.
5. Prepends `header_len` as 4-byte little-endian.
6. Returns the concatenated bytes: `[len][header][payload]`.

### `read_bundle<T: DeserializeOwned>`

```rust
pub fn read_bundle<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<(BundleHeader, T), String>
```

1. Reads `header_len` from first 4 bytes.
2. Deserializes `BundleHeader`.
3. Validates `magic == b"FRC1"`.
4. Validates `version <= BUNDLE_VERSION` (forward-incompatible, backward-compatible).
5. Computes `BLAKE3(payload_bytes)` and compares against `header.checksum`.
6. Deserializes and returns `(header, payload)`.

---

## CS Theory

| Concept | Where Used |
|---|---|
| **Content-addressed storage** | BLAKE3 checksum of the payload — the file is self-verifying |
| **Binary serialization** | `bincode` for deterministic, zero-allocation deserialization |
| **Protocol negotiation** | Magic bytes + version field (analogous to ELF/PNG file signatures) |
| **Forward compatibility** | Version gate: engine rejects bundles with version > its own |

---

## Design Decisions

**Why BLAKE3 and not SHA-256?**  
BLAKE3 is faster than SHA-256 on modern hardware (~1 GB/s single-core vs. ~500 MB/s) with equivalent security guarantees. For a 17 MB corpus file this matters during repeated loading in CI environments.

**Why `bincode` and not JSON or MessagePack?**  
`bincode` is designed for Rust structs with deterministic field ordering. JSON is human-readable but 3-4× larger. MessagePack is language-agnostic but requires schema negotiation. Since both writer (bundler) and reader (engine) are Rust programs sharing the same struct definitions, `bincode` is the natural choice.

**Why the 4-byte header-length prefix?**  
To allow streaming deserialization: the reader knows exactly how many bytes to read for the header without scanning for a delimiter. This is a common pattern in binary protocols (e.g., protobuf length-delimited framing).
