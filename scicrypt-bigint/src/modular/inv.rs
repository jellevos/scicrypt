use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS, scratch::Scratch};

impl BigInteger {
    /// Computes `self^-1 mod modulus`, taking ownership of `self`. Returns None if no inverse exists. `modulus` must be odd.
    pub fn invert(self, modulus: &BigInteger) -> Option<BigInteger> {
        // TODO: Verify that the input must be smaller than the modulus (is this indeed true?)
        //assert_eq!(self.supposed_size, modulus.supposed_size);
        //self.supposed_size = modulus.inner.size as i64;

        debug_assert_eq!(modulus.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, modulus.value.size, "the modulus' size in bits must match its actual size");
        //debug_assert_eq!(modulus.size_in_bits as i32, modulus.value.size * GMP_NUMB_BITS as i32, "the modulus' size in bits must be tight with its actual size");
        debug_assert_eq!(modulus.size_in_bits, self.size_in_bits, "the modulus must have the same size as self");

        // FIXME: This is not constant-time
        //debug_assert_eq!(modulus.value.size, self.value.size, "the modulus must have the same actual size as self");
        // if self.value.size != modulus.value.size {
        //     self += modulus;
        // }
        debug_assert_eq!(modulus.value.size, self.value.size, "the modulus must have the same actual size as self");

        //self += modulus;

        let mut result = BigInteger::init(modulus.value.size);

        unsafe {
            let scratch_size = gmp::mpn_sec_invert_itch(modulus.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            let is_valid = gmp::mpn_sec_invert(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                modulus.value.d.as_ptr(),
                modulus.value.size as i64,
                (self.size_in_bits + modulus.size_in_bits) as u64,
                scratch.as_mut(),
            );

            // Check if an inverse exists
            if is_valid == 0 {
                return None;
            }

            result.value.size = modulus.value.size;
            result.size_in_bits = modulus.size_in_bits;
            return Some(result);
        }
    }
}
