//! Diffie-Hellman key exchange using the [Ristretto255][ristretto]
//! group, in pure Rust.
//!
//! This crate provides a high-level API for static and ephemeral
//! Diffie-Hellman in the Ristretto255 prime order group as specified
//! in the [IETF draft][ietf-draft], implemented internally over (the
//! Edwards form of) Curve25519 using [curve25519-dalek].
//!
//! ## Example
//!
//! ```
//! use rand_core::OsRng;
//!
//! use ristretto255_dh::EphemeralSecret;
//! use ristretto255_dh::PublicKey;
//!
//! // Alice's side
//! let alice_secret = EphemeralSecret::new(&mut OsRng);
//! let alice_public = PublicKey::from(&alice_secret);
//!
//! // Bob's side
//! let bob_secret = EphemeralSecret::new(&mut OsRng);
//! let bob_public = PublicKey::from(&bob_secret);
//!
//! // Alice again
//! let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
//!
//! // Bob again
//! let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
//!
//! // Each peer's computed shared secret should be the same.
//! assert_eq!(
//!         <[u8; 32]>::from(alice_shared_secret),
//!         <[u8; 32]>::from(bob_shared_secret)
//! );
//! ```
//!
//! ## About
//!
//! The high-level Diffie-Hellman API is inspired by [x25519-dalek].
//!
//! [curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
//! [ietf-draft]: https://ietf.org/id/draft-irtf-cfrg-ristretto255-00.html
//! [ristretto]: https://ristretto.group
//! [x25519-dalek]: https://github.com/dalek-cryptography/x25519-dalek
#![doc(html_root_url = "https://docs.rs/ristretto255-dh/0.1.0")]

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use proptest::{arbitrary::Arbitrary, array, prelude::*};

/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that only exists for a short time.
#[cfg_attr(test, derive(Debug))]
pub struct EphemeralSecret(pub(crate) Scalar);

#[cfg(test)]
impl From<[u8; 32]> for EphemeralSecret {
    fn from(bytes: [u8; 32]) -> Self {
        match Scalar::from_canonical_bytes(bytes) {
            Some(scalar) => Self(scalar),
            None => Self(Scalar::from_bytes_mod_order(bytes)),
        }
    }
}

impl EphemeralSecret {
    /// Generate a `EphemeralSecret` using a new scalar mod the group
    /// order.
    pub fn new<T>(mut rng: T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        Self(Scalar::random(&mut rng))
    }

    /// Do Diffie-Hellman key agreement between self's secret
    /// and a peer's public key, resulting in a `SharedSecret`.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.0 * peer_public.0)
    }
}

#[cfg(test)]
impl Arbitrary for EphemeralSecret {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_filter("Valid scalar mod l", |b| {
                Scalar::from_bytes_mod_order(*b).is_canonical()
            })
            .prop_map(|bytes| return Self::from(bytes))
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

/// The public key derived from an ephemeral or static secret key.
#[derive(Clone, Copy, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(secret: &'a EphemeralSecret) -> Self {
        Self(&secret.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl From<PublicKey> for [u8; 32] {
    /// Copy the bytes of the internal `RistrettoPoint` as the
    /// canonical compressed wire format. Two `RistrettoPoint`s (and
    /// thus two `PublicKey`s) are equal iff their encodings are
    /// equal.
    fn from(public_key: PublicKey) -> Self {
        public_key.0.compress().to_bytes()
    }
}

impl<'a> From<&'a StaticSecret> for PublicKey {
    fn from(secret: &'a StaticSecret) -> Self {
        Self(&secret.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl From<[u8; 32]> for PublicKey {
    /// Attempts to decompress an internal `RistrettoPoint` from the
    /// input bytes, which should be the canonical compressed encoding
    /// of a `RistrettoPoint`.
    fn from(bytes: [u8; 32]) -> Self {
        Self(
            CompressedRistretto::from_slice(&bytes)
                .decompress()
                .unwrap(),
        )
    }
}

#[cfg(test)]
impl Arbitrary for PublicKey {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_filter(
                "Valid ristretto point",
                |b| match CompressedRistretto::from_slice(b).decompress() {
                    Some(_) => true,
                    None => false,
                },
            )
            .prop_map(|bytes| return Self::from(bytes))
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

/// A Diffie-Hellman shared secret derived from an `EphemeralSecret`
/// or `StaticSecret` and the other party's `PublicKey`.
pub struct SharedSecret(pub(crate) RistrettoPoint);

impl From<SharedSecret> for [u8; 32] {
    /// Copy the bytes of the internal `RistrettoPoint` as the
    /// canonical compressed wire format. Two `RistrettoPoint`s (and
    /// thus two `PublicKey`s) are equal iff their encodings are
    /// equal.
    fn from(shared_secret: SharedSecret) -> Self {
        shared_secret.0.compress().to_bytes()
    }
}

/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that can be stored and loaded.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct StaticSecret(pub(crate) Scalar);

impl From<[u8; 32]> for StaticSecret {
    fn from(bytes: [u8; 32]) -> Self {
        match Scalar::from_canonical_bytes(bytes) {
            Some(scalar) => Self(scalar),
            None => Self(Scalar::from_bytes_mod_order(bytes)),
        }
    }
}

impl StaticSecret {
    /// Generate a `StaticSecret` using a new scalar mod the group
    /// order.
    pub fn new<T>(mut rng: T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        Self(Scalar::random(&mut rng))
    }

    /// Do Diffie-Hellman key agreement between self's secret
    /// and a peer's public key, resulting in a `SharedSecret`.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.0 * peer_public.0)
    }
}

#[cfg(test)]
impl Arbitrary for StaticSecret {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_filter("Valid scalar mod l", |b| {
                Scalar::from_bytes_mod_order(*b).is_canonical()
            })
            .prop_map(|bytes| return Self::from(bytes))
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[cfg(test)]
mod tests {

    use bincode;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn random_dh() {
        let alice_secret = EphemeralSecret::new(&mut OsRng);
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::new(&mut OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(
            <[u8; 32]>::from(alice_shared_secret),
            <[u8; 32]>::from(bob_shared_secret)
        );
    }

    proptest! {

        #[test]
        fn ephemeral_dh(
            alice_secret in any::<EphemeralSecret>(),
            bob_secret in any::<EphemeralSecret>()
        ) {
            let alice_public = PublicKey::from(&alice_secret);
            let bob_public = PublicKey::from(&bob_secret);

            let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
            let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

            prop_assert_eq!(
                <[u8; 32]>::from(alice_shared_secret),
                <[u8; 32]>::from(bob_shared_secret)
            );
        }

        #[test]
        fn static_dh(
            alice_secret in any::<StaticSecret>(),
            bob_secret in any::<StaticSecret>()
        ) {
            let alice_public = PublicKey::from(&alice_secret);
            let bob_public = PublicKey::from(&bob_secret);

            let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
            let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

            prop_assert_eq!(
                <[u8; 32]>::from(alice_shared_secret),
                <[u8; 32]>::from(bob_shared_secret)
            );
        }

        #[test]
        fn serde_pubkey(alice_secret in any::<EphemeralSecret>()) {
            let alice_public = PublicKey::from(&alice_secret);

            let serialized = bincode::serialize(&alice_public).unwrap();

            prop_assert_eq!(
                alice_public, bincode::deserialize(&serialized[..]).unwrap()
            );
        }

        #[test]
        fn serde_static_key(alice_secret in any::<StaticSecret>()) {
            let serialized = bincode::serialize(&alice_secret).unwrap();

            prop_assert_eq!(
                alice_secret, bincode::deserialize(&serialized[..]).unwrap()
            );
        }

        #[test]
        fn from_into_pubkey_bytes(pubkey in any::<PublicKey>()) {
            let bytes: [u8; 32] = pubkey.into();

            prop_assert_eq!(
                pubkey, PublicKey::from(bytes)
            );
        }

    }
}
