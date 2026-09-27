#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![deny(clippy::unused_async)]

mod hybrid_kem;
mod kem;
mod rng;

/// An internal error type.
///
/// We do not distinguish decoding/decryption errors internally,
/// since best practice is to convert them all into the same
/// rustcrypto error.
struct Fail;

#[cfg(feature = "x25519")]
pub use hybrid_kem::X25519MlKem768;

#[cfg(feature = "p256")]
pub use hybrid_kem::Secp256R1MlKem768;

#[cfg(feature = "p384")]
pub use hybrid_kem::Secp384R1MlKem1024;

#[cfg(all(feature = "x25519", feature = "thread_rng"))]
pub use hybrid_kem::X25519MLKEM768;

#[cfg(all(feature = "p256", feature = "thread_rng"))]
pub use hybrid_kem::SECP256R1MLKEM768;

#[cfg(all(feature = "p384", feature = "thread_rng"))]
pub use hybrid_kem::SECP384R1MLKEM1024;

/// Add all compiled-in groups to a provided `CryptoProvider`,
/// placing them at the beginning of its preference order.
///
/// All ephemeral keys will be generated using [`rand::rng`].
/// If you prefer to use another RNG,
/// use one of the provided methods to construct the desired groups
/// yourself.
#[cfg(all(
    feature = "thread_rng",
    any(feature = "x25519", feature = "p256", feature = "p384")
))]
pub fn prepend_all_groups(provider: &mut rustls::crypto::CryptoProvider) {
    use rustls::crypto::SupportedKxGroup as G;

    provider.kx_groups.reverse();

    let mut perhaps_add = |group: &'static dyn G| {
        if !provider.kx_groups.iter().any(|g| g.name() == group.name()) {
            provider.kx_groups.push(group);
        }
    };

    #[cfg(feature = "x25519")]
    perhaps_add(&X25519MLKEM768);
    #[cfg(feature = "p256")]
    perhaps_add(&SECP256R1MLKEM768);
    #[cfg(feature = "p384")]
    perhaps_add(&SECP384R1MLKEM1024);

    provider.kx_groups.reverse();
}
