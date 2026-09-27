//! Wrappers for various RNG types and traits.

use rustls::crypto::SecureRandom;

/// An implementation of rustls's `SecureRandom` trait based on using [`rand::rng`].
#[cfg(any(test, feature = "thread_rng"))]
#[derive(Debug)]
pub(crate) struct UseThreadRng;

#[cfg(any(test, feature = "thread_rng"))]
impl SecureRandom for UseThreadRng
where
    rand::rngs::ThreadRng: rand::CryptoRng,
{
    fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core_10::TryRng as _;
        let mut rng = rand::rng();
        rng.try_fill_bytes(buf)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
    fn fips(&self) -> bool {
        false
    }
}

/// An implementation of `rand_core`'s  traits based on using rustls's [`SecureRandom`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct DynRandom(pub(crate) &'static dyn SecureRandom);

/// An error representing a failure from a `SecureRandom`.
///
/// (We need to define our own type since `rustls::crypto::GetrandomFailed`
/// doesn't implement `std::error::Error`).
#[derive(thiserror::Error, Debug)]
#[error("Unable to get bytes from SecureRandom.")]
struct SecureRandomFailed;

impl rand_core_06::RngCore for DynRandom {
    fn next_u32(&mut self) -> u32 {
        let mut a = [0_u8; 4];
        self.0.fill(&mut a[..]).expect("GetRandom failed.");
        u32::from_le_bytes(a)
    }
    fn next_u64(&mut self) -> u64 {
        let mut a = [0_u8; 8];
        self.0.fill(&mut a[..]).expect("GetRandom failed.");
        u64::from_le_bytes(a)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest).expect("GetRandom failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill(dest).map_err(|_| {
            let e: Box<dyn std::error::Error + Send + Sync + 'static> =
                Box::new(SecureRandomFailed);
            rand_core_06::Error::new(e)
        })
    }
}

impl rand_core_06::CryptoRng for DynRandom {}

// -----------------------------------------------------------------------------
// ml-kem 0.3 richiede rand_core 0.10 (TryRng/TryCryptoRng/CryptoRng).
// Implementiamo gli stessi trait su DynRandom sopra lo stesso SecureRandom.
// L'errore e' Infallibile: un fallimento di SecureRandom e' gia' catastrofico
// (le impl rand_core_06 qui sopra fanno .expect() per lo stesso motivo).
// -----------------------------------------------------------------------------

impl rand_core_10::TryRng for DynRandom {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut a = [0_u8; 4];
        self.0.fill(&mut a[..]).expect("GetRandom failed.");
        Ok(u32::from_le_bytes(a))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut a = [0_u8; 8];
        self.0.fill(&mut a[..]).expect("GetRandom failed.");
        Ok(u64::from_le_bytes(a))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(dest).expect("GetRandom failed.");
        Ok(())
    }
}

// rand_core_10::Rng e' blanket-impl'd per TryRng<Error=Infallible>;
// rand_core_10::CryptoRng lo e' per TryCryptoRng<Error=Infallible>+Rng.
impl rand_core_10::TryCryptoRng for DynRandom {}
