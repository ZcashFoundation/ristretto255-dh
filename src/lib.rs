#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]

use std::convert::TryFrom;

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use proptest::{arbitrary::Arbitrary, array, collection, prelude::*};

/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that only exists for a short time.
#[cfg_attr(test, derive(Debug))]
pub struct EphemeralSecret(pub(crate) Scalar);

impl From<[u8; 32]> for EphemeralSecret {
    fn from(bytes: [u8; 32]) -> EphemeralSecret {
        match Scalar::from_canonical_bytes(bytes) {
            Some(scalar) => Self(scalar),
            None => Self(Scalar::from_bytes_mod_order(bytes)),
        }
    }
}

impl From<[u8; 64]> for EphemeralSecret {
    fn from(bytes: [u8; 64]) -> EphemeralSecret {
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }
}

impl EphemeralSecret {
    /// Generate a `EphemeralSecret` using a new scalar mod the group
    /// order.
    pub fn new<T>(mut rng: T) -> EphemeralSecret
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
        array::uniform32(any::<u8>()).prop_map_into().boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

/// The public key derived from an ephemeral or static secret key.
#[derive(Clone, Copy, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(secret: &'a EphemeralSecret) -> PublicKey {
        Self(&secret.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl From<PublicKey> for [u8; 32] {
    /// Copy the bytes of the internal `RistrettoPoint` as the
    /// canonical compressed wire format. Two `RistrettoPoint`s (and
    /// thus two `PublicKey`s) are equal iff their encodings are
    /// equal.
    fn from(public_key: PublicKey) -> [u8; 32] {
        public_key.0.compress().to_bytes()
    }
}

impl<'a> From<&'a StaticSecret> for PublicKey {
    fn from(secret: &'a StaticSecret) -> PublicKey {
        Self(&secret.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<[u8; 32]> for PublicKey {
    type Error = &'static str;

    /// Attempts to decompress an internal `RistrettoPoint` from the
    /// input bytes, which should be the canonical compressed encoding
    /// of a `RistrettoPoint`.
    fn try_from(bytes: [u8; 32]) -> Result<PublicKey, Self::Error> {
        match CompressedRistretto::from_slice(&bytes).decompress() {
            Some(ristretto_point) => Ok(Self(ristretto_point)),
            None => Err("Ristretto point decompression failed"),
        }
    }
}

#[cfg(test)]
impl Arbitrary for PublicKey {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_filter_map("Decompressible Ristretto point", |b| {
                PublicKey::try_from(b).ok()
            })
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
    fn from(shared_secret: SharedSecret) -> [u8; 32] {
        shared_secret.0.compress().to_bytes()
    }
}

/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that can be stored and loaded.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct StaticSecret(pub(crate) Scalar);

impl From<StaticSecret> for [u8; 32] {
    fn from(static_secret: StaticSecret) -> [u8; 32] {
        static_secret.0.to_bytes()
    }
}

impl From<[u8; 32]> for StaticSecret {
    fn from(bytes: [u8; 32]) -> StaticSecret {
        match Scalar::from_canonical_bytes(bytes) {
            Some(scalar) => Self(scalar),
            None => Self(Scalar::from_bytes_mod_order(bytes)),
        }
    }
}

impl From<[u8; 64]> for StaticSecret {
    fn from(bytes: [u8; 64]) -> StaticSecret {
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }
}

impl StaticSecret {
    /// Generate a `StaticSecret` using a new scalar mod the group
    /// order.
    pub fn new<T>(mut rng: T) -> StaticSecret
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
        fn random_dh_wide(alice_bytes in collection::vec(any::<u8>(), 64),
                          bob_bytes in collection::vec(any::<u8>(), 64)) {
            let mut a = [0u8; 64];
            a.copy_from_slice(alice_bytes.as_slice());

            let alice_secret = EphemeralSecret::from(a);
            let alice_public = PublicKey::from(&alice_secret);

            let mut b = [0u8; 64];
            b.copy_from_slice(bob_bytes.as_slice());

            let bob_secret = StaticSecret::from(b);
            let bob_public = PublicKey::from(&bob_secret);

            let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
            let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

            assert_eq!(
                <[u8; 32]>::from(alice_shared_secret),
                <[u8; 32]>::from(bob_shared_secret)
            );
        }

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
                Ok(pubkey), PublicKey::try_from(bytes)
            );
        }

        #[test]
        fn from_into_static_secret_bytes(static_secret in any::<StaticSecret>()) {
            let bytes: [u8; 32] = static_secret.into();

            prop_assert_eq!(
                static_secret, StaticSecret::from(bytes)
            );
        }

        #[test]
        fn scalar_mul_different_paths(
            secret in any::<EphemeralSecret>(),
        ) {
            let other_public = PublicKey(constants::RISTRETTO_BASEPOINT_POINT * secret.0);

            prop_assert_eq!(
                other_public,
                PublicKey::from(&secret)
            );
        }

    }
}
