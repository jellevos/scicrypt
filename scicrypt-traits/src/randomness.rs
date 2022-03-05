use rug::rand::{ThreadRandGen, ThreadRandState};

pub trait SecureRng = rand_core::RngCore + rand_core::CryptoRng;

/// General RNG that can be used for all dependencies.
pub struct GeneralRng<R: SecureRng> {
    rng_wrapper: RngWrapper<R>,
}

impl<R: SecureRng> GeneralRng<R> {
    /// Creates a new `SecureRng` based on an RNG that implements both `RngCore` and `CryptoRng` to
    /// ensure that the underlying RNG is indeed cryptographically secure.
    pub fn new(rng: R) -> Self {
        GeneralRng {
            rng_wrapper: RngWrapper { rng },
        }
    }

    /// Exposes the underlying RNG.
    pub fn rng(&mut self) -> &mut R {
        &mut self.rng_wrapper.rng
    }

    /// Creates a RNG for the `rug` crate that is only suitable for a single thread.
    pub fn rug_rng(&mut self) -> ThreadRandState<'_> {
        ThreadRandState::new_custom(&mut self.rng_wrapper)
    }
}

struct RngWrapper<R: SecureRng> {
    rng: R,
}

impl<R: SecureRng> ThreadRandGen for RngWrapper<R> {
    fn gen(&mut self) -> u32 {
        self.rng.next_u32()
    }
}
