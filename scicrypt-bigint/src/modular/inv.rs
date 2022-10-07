use subtle::{ConditionallySelectable, Choice};

use crate::UnsignedInteger;

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    pub fn invert(mut self, modulus: &UnsignedInteger<LIMB_COUNT>) -> Option<UnsignedInteger<LIMB_COUNT>> {
        let mut u = UnsignedInteger::from(1);
        let mut v = UnsignedInteger::zero();

        let mut b = *modulus;

        // TODO: This can be lower if `self` is known to be small.
        let bit_size = 2 * LIMB_COUNT * 64;

        let mut m1hp = modulus.clone();
        let carry = m1hp.shift_right_1();
        debug_assert!(carry.unwrap_u8() == 1);
        let carry = m1hp.add_u64_and_carry(1);
        debug_assert!(carry.unwrap_u8() == 0);

        for _ in 0..bit_size {
            debug_assert!(b.is_odd().unwrap_u8() == 1);

            let self_odd = self.is_odd();

            // Set `self -= b` if `self` is odd.
            let swap = self.subtract_and_carry_conditionally(&b, self_odd);
            // Set `b += self` if `swap` is true.
            b = UnsignedInteger::conditional_select(&b, &(b + &self), swap);
            // Negate `self` if `swap` is true.
            self = self.negate_conditionally(swap);

            UnsignedInteger::conditional_swap(&mut u, &mut v, swap);
            let cy = u.subtract_and_carry_conditionally(&v, self_odd);
            let cyy = u.add_and_carry_conditionally(modulus, cy);
            debug_assert_eq!(cy.unwrap_u8(), cyy.unwrap_u8());

            let overflow = self.shift_right_1();
            debug_assert!(overflow.unwrap_u8() == 0);
            let cy = u.shift_right_1();
            let cy = u.add_and_carry_conditionally(&m1hp, cy);
            debug_assert!(cy.unwrap_u8() == 0);
        }

        debug_assert_eq!(self, 0);

        if b != 1 {
            None
        } else {
            Some(v)
        }
    }
}

// impl UnsignedInteger {
//     /// Computes `self^-1 mod modulus`, taking ownership of `self`. Returns None if no inverse exists. `modulus` must be odd.
//     pub fn invert(self, modulus: &UnsignedInteger) -> Option<UnsignedInteger> {
//         // TODO: Verify that the input must be smaller than the modulus (is this indeed true?)
//         debug_assert!(self.value.size.is_positive());
//         debug_assert!(modulus.value.size.is_positive());

//         debug_assert_eq!(
//             modulus.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
//             modulus.value.size,
//             "the modulus' size in bits must match its actual size"
//         );
//         //debug_assert_eq!(modulus.size_in_bits as i32, modulus.value.size * GMP_NUMB_BITS as i32, "the modulus' size in bits must be tight with its actual size");
//         // debug_assert_eq!(
//         //     modulus.size_in_bits, self.size_in_bits,
//         //     "the modulus must have the same size as self"
//         // );
//         debug_assert_eq!(
//             modulus.value.size, self.value.size,
//             "the modulus must have the same size as self"
//         );

//         debug_assert_eq!(
//             modulus.value.size, self.value.size,
//             "the modulus must have the same actual size as self"
//         );

//         let mut result = UnsignedInteger::init(modulus.value.size);

//         unsafe {
//             let scratch_size = gmp::mpn_sec_invert_itch(modulus.value.size as i64) as usize
//                 * GMP_NUMB_BITS as usize;

//             let mut scratch = Scratch::new(scratch_size);

//             let is_valid = gmp::mpn_sec_invert(
//                 result.value.d.as_mut(),
//                 self.value.d.as_ptr(),
//                 modulus.value.d.as_ptr(),
//                 modulus.value.size as i64,
//                 (self.size_in_bits + modulus.size_in_bits) as u64,
//                 scratch.as_mut(),
//             );

//             // Check if an inverse exists
//             if is_valid == 0 {
//                 return None;
//             }

//             result.value.size = modulus.value.size;
//             result.size_in_bits = modulus.size_in_bits;
//             Some(result)
//         }
//     }

//     /// Computes `self^-1 mod modulus`, taking ownership of `self`. Returns None if no inverse exists. `modulus` must be odd. This function is not constant-time.
//     pub fn invert_leaky(mut self, modulus: &UnsignedInteger) -> Option<UnsignedInteger> {
//         unsafe {
//             let is_valid = mpz_invert(&mut self.value, &self.value, &modulus.value);

//             // Check if an inverse exists
//             if is_valid == 0 {
//                 return None;
//             }

//             self.value.size = modulus.value.size;
//             self.size_in_bits = modulus.size_in_bits;
//             Some(self)
//         }
//     }
// }


#[cfg(test)]
mod tests {
    use subtle::Choice;

    use crate::{UnsignedInteger, U1024};

    #[test]
    fn test_invert() {
        let a = U1024::from_str_leaky("5892358416859326896589748197812740739507917092740973905700591759793209771117197329023975932757523759072735959723097537209079532975039297099714397901428947253853027537265853823285397084380934928703270590758520818187287349487329243789243783249743289423789918417987091287932757258397104397295856325791091077", 10);
        let m = U1024::from_str_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471", 10);

        let res = a.invert(&m);

        let expected = UnsignedInteger::from_str_leaky("123739905086158212270843051527441649600807330749471895683394889028867514801710371562360352272055594352035190616471030275978939424413601977497555131069474726813170115491482106601865630839838144362329125370518957163898801175903502017426241817312333816497160685389024867847545777202327273987093691380956370608950", 10);
        assert_eq!(res.unwrap(), expected);
    }

    #[test]
    fn test_invert_small() {
        let a = UnsignedInteger::<1>::from(3u64);
        let m = UnsignedInteger::from(13u64);

        let res = a.invert(&m);

        assert_eq!(UnsignedInteger::from(9u64), res.unwrap());
    }

    #[test]
    fn test_no_inverse_small() {
        let a = UnsignedInteger::<1>::from(14u64);
        let m = UnsignedInteger::from(49u64);

        let res = a.invert(&m);

        assert!(res.is_none());
    }
}
