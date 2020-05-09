# ristretto255-dh [![](https://img.shields.io/crates/v/ristretto255-dh.svg)](https://crates.io/crates/ristretto255-dh) [![](https://docs.rs/ristretto255-dh/badge.svg)](https://docs.rs/ristretto255-dh) [![](https://github.com/ZcashFoundation/ristretto255-dh/workflows/CI/badge.svg?branch=main)](https://github.com/ZcashFoundation/ristretto255-dh/actions?query=workflow%3ACI+branch%3Amain)

Diffie-Hellman key exchange using the [Ristretto255][ristretto] group,
in pure Rust.

This crate provides a high-level API for static and ephemeral
Diffie-Hellman in the Ristretto255 prime order group, as specified the
[IETF draft][ietf-draft], implemented internally over Curve25519 using
[curve25519-dalek].

## Example

```rust
use rand_core::OsRng;

use ristretto255_dh::EphemeralSecret;
use ristretto255_dh::PublicKey;

// Alice's side
let alice_secret = EphemeralSecret::new(&mut OsRng);
let alice_public = PublicKey::from(&alice_secret);

// Bob's side
let bob_secret = EphemeralSecret::new(&mut OsRng);
let bob_public = PublicKey::from(&bob_secret);

// Alice again
let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

// Bob again
let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

// Each peer's computed shared secret should be the same.
assert_eq!(<[u8; 32]>::from(alice_shared_secret), <[u8; 32]>::from(bob_shared_secret));
```

## About

The high-level Diffie-Hellman API is inspired by [x25519-dalek].

[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
[ietf-draft]: https://ietf.org/id/draft-irtf-cfrg-ristretto255-00.html
[ristretto]: https://ristretto.group
[x25519-dalek]: https://github.com/dalek-cryptography/x25519-dalek

