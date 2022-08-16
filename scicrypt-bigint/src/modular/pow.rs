use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS, scratch::Scratch};

impl BigInteger {
    /// Compute `self` to the power `exponent` modulo an odd `modulus`. The computation takes time that scales with the specified size of the `exponent` and `modulus`.
    pub fn pow_mod(&self, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
        debug_assert!(!self.is_zero(), "the base must be larger than 0");
        debug_assert!(!modulus.is_zero(), "the modulus must be larger than 0");
        // TODO: debug_assert!() that the modulus is ODD
        // TODO: debug_assert!() that the exponent's bitsize is smaller than its size_in_bits
        debug_assert!(exponent.size_in_bits > 0, "the exponent must be larger than 0");

        debug_assert_eq!(modulus.size_in_bits as i32, modulus.value.size * GMP_NUMB_BITS as i32, "the modulus' size in bits must be tight with its actual size");

        // TODO: Probably we should also assert that the modulus does not contain less limbs than the other operands

        let mut result = BigInteger::init(modulus.value.size);

        let enb = exponent.size_in_bits as u64;

        unsafe {
            let scratch_size =
                gmp::mpn_sec_powm_itch(self.value.size as i64, enb, modulus.value.size as i64) as usize
                    * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_powm(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                exponent.value.d.as_ptr(),
                enb,
                modulus.value.d.as_ptr(),
                modulus.value.size as i64,
                scratch.as_mut(),
            );

            result.value.size = modulus.value.size;
            result
        }
    }
}
