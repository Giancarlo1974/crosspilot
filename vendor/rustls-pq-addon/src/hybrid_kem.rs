//! Implement the TLS hybrid KEMs
//!
//! Specifically, this module implements the three hybrid KEMs from
//! [draft-ietf-tls-ecdhe-mlkem].
//!
//! ## Implementation strategy
//!
//! Fortunately, this standard is pretty simple.
//! All key_exchange shares, and all shared secrets, are fixed length.
//!
//! We treat each part of the hybrid KEM as an underlying KEM,
//! and build using them generically.  (I'd like to use a more generic
//! approach (rather than all these macros), but const generics are
//! still a bit under-powered, and `hybrid_array` doesn't support all the
//! sizes we need.)
//!
//! We process all inputs as fixed-length arrays, checking their size
//! immediately.  We build outputs directly into ByteVecs of known
//! capacity, so that we never have to reallocate (and potentially
//! leave stale data on the heap).
//!
//! ## Security notes
//!
//! ### Side channel resistence
//!
//! We require that our underlying implementations resist timing side channels.
//!
//! For a failed negotiation, we do not ourselves attempt to hide the
//! point at which negotiation failed: that's unnecessary with TLS1.3.
//! (No other implementation I've seen tries to hide this.)
//!
//! ### Requirements from the standard
//!
//! The standard has the following requirements:
//!
//! > For all groups, the server MUST perform the encapsulation key check
//! > described in Section 7.2 of [NIST-FIPS-203] on the client's
//! > encapsulation key, and abort with an illegal_parameter alert if it
//! > fails.
//!
//! The current version (0.2.3) of the [`ml_kem`] crate doesn't do that;
//! we do it ourselves in [crate::encoding].
//!
//! > For all groups, the client MUST check if the ciphertext length
//! > matches the selected group, and abort with an illegal_parameter alert
//! > if it fails.  If ML-KEM decapsulation fails for any other reason, the
//! > connection MUST be aborted with an internal_error alert.
//!
//! We check every message length immediately on entering the function.
//! Further, our [`Decodable`] trait enforces the property that we only
//! decode fixed-size messages of the right length.
//!
//! > For all groups, both client and server MUST process the ECDH part as
//! > described in Section 4.2.8.2 of [RFC8446], including all validity
//! > checks, and abort with an illegal_parameter alert if it fails."
//!
//! The p256 and p384 implementations reject the identity point, and
//! any point not on the curve, in `PublicKey::from_sec1_bytes`.
//!
//! Our x25519 KEM wrapper rejects outputs from non-contributory key exchanges.
//!
//! > [NIST-SP-800-227] includes guidelines and requirements for
//! > implementations on using KEMs securely.  Implementers are encouraged
//! > to use implementations resistant to side-channel attacks, especially
//! > those that can be applied by remote attackers."
//!
//! - The underlying KEMs are, or claim to be trying to be,
//!   side-channel resistant.
//! - All inputs are checked as above.
//! - The underlying KEMs, and the rustls library, take some pains to
//!   clear private keys after they are dropped.
//! - The EC crates we use zeroize shared secrets on drop.
//! - The ml_kem crate returns its shared secrets as Arrays.
//!   We build all shared secrets using our Encodable trait,
//!   which ensures that arrays are zeroized on drop.
//! - Our ByteVec wrapper ensures that we never realloc() an
//!   in-progress secret and leak it on the heap.
//!
//! (This is quite a long document, though!)
//!
//! [draft-ietf-tls-ecdhe-mlkem]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
//! [NIST-SP-800-227]: https://csrc.nist.gov/pubs/sp/800/227/final
//! [RFC8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
//! [NIST-FIPS-203]: https://csrc.nist.gov/pubs/fips/203/final

// XXXX MUST DO:
//
//  - Question -- Am I doing anything wrong with the various early returns
//    in the functions below?  They leak where the process failed, if the
//    process failed.
//
// TODO Later:
//    o consider allowing non-ThreadRng rngs?
//    o Stop using hybrid_array.
//    o Move everything around.
//    o Document everything.
//    o Turn on more clippy warnings.
//    o Test with msrv
//    - CI.
//    - minimize features needed from other crates
//    o State this this crate will only ever be hybrid.
//    - Read the openssl implementation to see whether I screwed anything up.
//
// TODO yet later:
//    - Update to x25519-dalek 3.0 when released.
//    - Update to ml-kem 0.3 when released.
//    - Consider taking ecdh implementations from an existing kx group?
//    - port EC to dhkem.
//    - Once rust const generics are more powerful, use them consistently.

// ml-kem 0.3: KemCore non esiste piu'; i key type sono
// ml_kem::DecapsulationKey<P> / EncapsulationKey<P> con P = MlKemNNN.

// use crate::encoding::{ByteVec, Decodable, Encodable};
use crate::kem::{ByteVec, ConcatHybrid, DecapKey, EncapKey};
use crate::rng::DynRandom;
#[cfg(feature = "thread_rng")]
use crate::rng::UseThreadRng;
// use crate::split_array::split_bytes;
use crate::Fail;
use paste::paste;

use rustls::crypto::SecureRandom;

impl From<Fail> for rustls::Error {
    fn from(_: Fail) -> rustls::Error {
        rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare)
    }
}

/// Define a Rustls SupportedKxGroup for a given hybrid key exchange.
macro_rules! define_hybrid_group {
    {
        // Public type name: the type that implements SupportedKxGroup.
        name: $name:ident,
        // The TLS NamedGroup that this group implements.
        named_group: $named_group:expr,
        // The TLS NamedGroup for the underlying elliptic-curve.
        ec_group: $ec_group:expr,
        // The secret key type for this group.
        sk: $sk:ty,
        // The public key type for this group.
        pk: $pk:ty,
        // Accessor: extract the EC group from the two groups.
        // (Used for hybrid optimization)
        select_ec: $select_ec:expr,
    } => {paste!{
        /// A rustls implementation for the
        #[doc = stringify!($grp)]
        /// hybrid key exchange group.
        ///
        /// To enable this, add it to a `rustls::crypto::CryptoProvider`'s `kx_groups`
        /// field.  Note that the kx_groups elements must be listed in preference order.
        ///
        /// If you don't care which (secure) RNG it uses, you may want to use
        #[doc = "[`" $name:upper "`]"]
        /// instead.
        #[derive(Debug)]
        pub struct $name {
            rng: DynRandom
        }

        /// A rustls implementation for the
        #[doc = stringify!($grp)]
        /// hybrid key exchange group.
        ///
        /// To enable this, add it to a `rustls::crypto::CryptoProvider`'s `kx_groups`
        /// field.  Note that the kx_groups elements must be listed in preference order.
        ///
        /// This implementation uses [`rand::rng`] for its secure RNG.
        /// If you want to use a different RNG, construct an instance of this type
        /// using
        #[doc = concat!("[`", stringify!($grp), "::new`].")]
        #[cfg(any(test, feature="thread_rng"))]
        pub static [< $name:upper >]: $name = $name { rng: DynRandom(&UseThreadRng) };

        impl $name {
            /// Construct a rustls implementation for the
            #[doc = stringify!($grp)]
            /// hybrid key exchange group.
            ///
            /// The generated implementation will use the provided RNG to generate
            /// its ephemeral keys.
            pub const fn new(rng: &'static dyn SecureRandom) -> Self {
                Self { rng: DynRandom(rng) }
            }
        }

        /// A client's state for an in-progress handshake.
        struct [< Active $name >] {
            /// The client's key_exchange share.
            ///
            /// This is just the concatenation of the EC public key and the MLKEM
            /// encapsulation key, in a group-dependent order.
            pk: Box<[u8]>,
            /// The secret key.
            sk: $sk,
        }

        impl rustls::crypto::SupportedKxGroup for $name {
            fn name(&self) -> rustls::NamedGroup {
                $named_group
            }

            fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
                None
            }

            fn fips(&self) -> bool {
                // This algorithm may or may not be fips-approved,
                // but this code definitely isn't.
                false
            }

            fn usable_for_version(&self, ver: rustls::ProtocolVersion) -> bool {
                use rustls::ProtocolVersion::*;
                matches!(ver, TLSv1_3 | DTLSv1_3)
            }

            /// Client-side: Generate the client's ephemeral keys and ClientKeyExchange message.
            fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
                let mut rng = self.rng;

                // Generate the keys.
                let (sk, pk) = <$sk>::from_rng(&mut rng);

                // Encode the public key.
                let mut pk_encoded = ByteVec::new(<$pk>::PUBKEY_LEN);
                pk.encode(&mut pk_encoded);

                // Create a new ActiveKeyExchange.
                Ok(Box::new([<Active $name>] {
                    pk: pk_encoded.into_vec().into(),
                    sk,
                }))
            }

            /// Server-side: Handle the server side of the key exchange.
            fn start_and_complete(
                &self,
                peer_pub_key: &[u8],
            ) -> Result<rustls::crypto::CompletedKeyExchange, rustls::Error> {
                let mut rng = self.rng;

                let peer_pk = <$pk>::decode(peer_pub_key)?;
                let mut msg_out = ByteVec::new(<$pk>::CIPHERTEXT_LEN);
                let mut secret_out = ByteVec::new(<$sk>::SECRET_LEN);

                peer_pk.encapsulate(&mut rng, &mut msg_out, &mut secret_out)?;
                Ok(rustls::crypto::CompletedKeyExchange {
                    group: $named_group,
                    pub_key: msg_out.into_vec(),
                    secret: rustls::crypto::SharedSecret::from(secret_out.into_vec())
                })
            }
        }

        impl rustls::crypto::ActiveKeyExchange for [< Active $name >] {
            fn group(&self) -> rustls::NamedGroup {
                $named_group
            }

            fn pub_key(&self) -> &[u8] {
                &self.pk[..]
            }

            /// Client-side: Handle the server's key_exchange share and establish our shared secret.
            fn complete(
                self: Box<Self>,
                peer_pub_key: &[u8],
            ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
                let mut secret_out = ByteVec::new(<$sk>::SECRET_LEN);
                self.sk.decapsulate(peer_pub_key, &mut secret_out)?;
                Ok(secret_out.into_vec().into())
            }

            /// Client-side optimization: This lets us send the elliptic curve part of this
            /// key_exchange share as its own separate key_exchange share.
            ///
            /// For example, this lets us send an x25519+mlkem768 key_share and an x25519 key share
            /// while generating only one x25519 public key.
            fn hybrid_component(&self) -> Option<(rustls::NamedGroup, &[u8])> {
                let (pk1, pk2) = <$pk>::split_pubkey(&self.pk[..]);
                Some(($ec_group, ($select_ec)(pk1, pk2)))
            }

            /// Client-side optimization: This lets us complete an elliptic curve handshake
            /// that began with `hybid_component`.
            fn complete_hybrid_component(
                self: Box<Self>,
                peer_pub_key: &[u8],
            ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
                let sk = ($select_ec)(self.sk.0, self.sk.1);
                let mut secret_out = ByteVec::new(sk.secret_len());
                sk.decapsulate(peer_pub_key, &mut secret_out)?;
                Ok(secret_out.into_vec().into())
            }
        }
    }}
}

/// ml-kem 768 decapsulation key
#[cfg(any(feature = "x25519", feature = "p256"))]
type MlKem768SecretKey = ml_kem::DecapsulationKey<ml_kem::MlKem768>;
/// ml-kem 768 encapsulation key
#[cfg(any(feature = "x25519", feature = "p256"))]
type MlKem768PublicKey = ml_kem::EncapsulationKey<ml_kem::MlKem768>;
/// ml-kem 1024 decapsulation key
#[cfg(feature = "p384")]
type MlKem1024SecretKey = ml_kem::DecapsulationKey<ml_kem::MlKem1024>;
/// ml-kem 1024 encapsulation key
#[cfg(feature = "p384")]
type MlKem1024PublicKey = ml_kem::EncapsulationKey<ml_kem::MlKem1024>;

/// Return the first argument.
#[cfg(any(feature = "p256", feature = "p384"))]
fn first<A, B>(a: A, _: B) -> A {
    a
}
/// Return the second argument.
#[cfg(feature = "x25519")]
fn second<A, B>(_: A, b: B) -> B {
    b
}

#[cfg(feature = "x25519")]
define_hybrid_group! {
    name: X25519MlKem768,
    named_group: rustls::NamedGroup::X25519MLKEM768,
    ec_group: rustls::NamedGroup::X25519,
    sk: ConcatHybrid<MlKem768SecretKey, x25519_dalek::EphemeralSecret>,
    pk: ConcatHybrid<MlKem768PublicKey, x25519_dalek::PublicKey>,
    // For historical reason, the X25519 key goes second in this key exchange.
    select_ec: second,
}

#[cfg(feature = "p256")]
define_hybrid_group! {
    name: Secp256R1MlKem768,
    named_group: rustls::NamedGroup::secp256r1MLKEM768,
    ec_group: rustls::NamedGroup::secp256r1,
    sk: ConcatHybrid<p256::ecdh::EphemeralSecret, MlKem768SecretKey>,
    pk: ConcatHybrid<p256::PublicKey, MlKem768PublicKey>,
    select_ec: first,
}

#[cfg(feature = "p384")]
define_hybrid_group! {
    name: Secp384R1MlKem1024,
    named_group: rustls::NamedGroup::from(0x11ED),
    ec_group: rustls::NamedGroup::secp384r1,
    sk: ConcatHybrid<p384::ecdh::EphemeralSecret, MlKem1024SecretKey>,
    pk: ConcatHybrid<p384::PublicKey, MlKem1024PublicKey>,
    select_ec: first,
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use rustls::crypto::SupportedKxGroup;

    fn test_roundtrip(client_group: &dyn SupportedKxGroup, server_group: &dyn SupportedKxGroup) {
        let client_state = client_group.start().unwrap();
        let server = server_group
            .start_and_complete(client_state.pub_key())
            .unwrap();
        let client_secret = client_state.complete(&server.pub_key).unwrap();

        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
    }

    //-------
    // Make sure that each group can round-trip with itself.

    #[cfg(feature = "x25519")]
    #[test]
    fn roundtrip_x25519mlkem768() {
        let group = &X25519MLKEM768;
        test_roundtrip(group, group);
    }

    #[cfg(feature = "p256")]
    #[test]
    fn roundtrip_secp256mlkem768() {
        let group = &SECP256R1MLKEM768;
        test_roundtrip(group, group);
    }

    #[cfg(feature = "p384")]
    #[test]
    fn roundtrip_secp384mlkem1024() {
        let group = &SECP384R1MLKEM1024;
        test_roundtrip(group, group);
    }

    // (Vendored) Rimossi i test di interop con rustls::crypto::aws_lc_rs:
    // richiederebbero il dev-dep aws-lc-rs (toolchain C), escluso dalla
    // build per scelta progettuale (docs/tls-pq-spec.md §10).
}
