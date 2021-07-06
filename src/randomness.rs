use rug::rand::{ThreadRandState, ThreadRandGen};

pub struct SecureRng<R: rand_core::RngCore + rand_core::CryptoRng> {
    rng_wrapper: RngWrapper<R>,
}

impl<R: rand_core::RngCore + rand_core::CryptoRng> SecureRng<R> {

    pub fn new(rng: R) -> Self {
        SecureRng {
            rng_wrapper: RngWrapper { rng },
        }
    }

    pub fn rng(&mut self) -> &mut R {
        &mut self.rng_wrapper.rng
    }

    pub fn rug_rng(&mut self) -> ThreadRandState<'_> {
        ThreadRandState::new_custom(&mut self.rng_wrapper)
    }

}

struct RngWrapper<R: rand_core::RngCore + rand_core::CryptoRng> {
    rng: R,
}

impl<R: rand_core::RngCore + rand_core::CryptoRng> ThreadRandGen for RngWrapper<R> {

    fn gen(&mut self) -> u32 {
        self.rng.next_u32()
    }

}
