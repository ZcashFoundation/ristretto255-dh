# ristretto255-dh
Diffie-Hellman key exchange using the [Ristretto255][ristretto] group, in pure Rust.

This crate provides a high-level API for static and ephemeral Diffie-Hellman in the Ristretto255 prime order group, as specified the [IETF draft][ietf-draft], implemented internally over Curve25519 using [curve25519-dalek]. 


## Example

```
use rand_os::OsRng;

use ristretto255_dh::EphemeralSecret;
use ristretto255_dh::PublicKey;

// Alice's side
let mut alice_csprng = OsRng::new().unwrap();
let     alice_secret = EphemeralSecret::new(&mut alice_csprng);
let     alice_public = PublicKey::from(&alice_secret);

// Bob's side
let mut bob_csprng = OsRng::new().unwrap();
let     bob_secret = EphemeralSecret::new(&mut bob_csprng);
let     bob_public = PublicKey::from(&bob_secret);

// Alice again
let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

// Bob again
let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

// Each peer's computed shared secret should be the same.
assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
```

# Installation

To install, add the following to your project's `Cargo.toml`:

```toml
[dependencies.ristretto255-dh]
version = "0.1.0"
```

## About

The high-level Diffie-Hellman API is inspired by [x25519-dalek]. 

[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
[ietf-draft]: https://ietf.org/id/draft-irtf-cfrg-ristretto255-00.html
[ristretto]: https://ristretto.group
[x25519-dalek]: https://github.com/dalek-cryptography/x25519-dalek

