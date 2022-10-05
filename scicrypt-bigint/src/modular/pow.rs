use crate::UnsignedInteger;

// impl UnsignedInteger {
//     /// Compute `self` to the power `exponent` modulo an odd `modulus`. The computation takes time that scales with the specified size of the `exponent` and `modulus`.
//     pub fn pow_mod(
//         &self,
//         exponent: &UnsignedInteger,
//         modulus: &UnsignedInteger,
//     ) -> UnsignedInteger {
//         if exponent.value.size == 0 {
//             return UnsignedInteger::new(1, 1);
//         }

//         debug_assert!(!self.is_zero_leaky(), "the base must not be 0");
//         debug_assert!(!modulus.is_zero_leaky(), "the modulus must not be 0");
//         // TODO: debug_assert!() that the modulus is ODD
//         // TODO: debug_assert!() that the exponent's bitsize is smaller than its size_in_bits
//         debug_assert!(
//             exponent.size_in_bits > 0,
//             "the exponent must be larger than 0"
//         );
//         debug_assert!(exponent.value.size.is_positive());

//         debug_assert!(self.value.size.is_positive());
//         debug_assert!(modulus.value.size.is_positive());

//         debug_assert_eq!(
//             modulus.size_in_bits.div_ceil(GMP_NUMB_BITS),
//             modulus.value.size as u32,
//             "the modulus' size in bits must be tight with its actual size"
//         );

//         // TODO: Probably we should also assert that the modulus does not contain less limbs than the other operands

//         let mut result = UnsignedInteger::init(modulus.value.size);

//         let enb = exponent.size_in_bits as u64;

//         unsafe {
//             let scratch_size =
//                 gmp::mpn_sec_powm_itch(self.value.size as i64, enb, modulus.value.size as i64)
//                     as usize
//                     * GMP_NUMB_BITS as usize;

//             let mut scratch = Scratch::new(scratch_size);

//             gmp::mpn_sec_powm(
//                 result.value.d.as_mut(),
//                 self.value.d.as_ptr(),
//                 self.value.size as i64,
//                 exponent.value.d.as_ptr(),
//                 enb,
//                 modulus.value.d.as_ptr(),
//                 modulus.value.size as i64,
//                 scratch.as_mut(),
//             );

//             result.value.size = modulus.value.size;
//             result
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    // #[test]
    // fn test_powmod_small_base() {
    //     let b = UnsignedInteger::from_string_leaky("105".to_string(), 10, 7);
    //     let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     let res = b.pow_mod(&e, &m);

    //     let expected = UnsignedInteger::from_string_leaky("93381698043531945590460734835437626929406390544089092303961497613088223192062266567807404255983003371786424645697784253062005750244340967243067126193405796382070980127325598311265307429963380264226672935938163271489566200721235534991781171263956580735259196276780705026850011214281556290838394235159210861122".to_string(), 10, 1024);
    //     assert_eq!(res, expected);
    // }

    // #[test]
    // fn test_powmod_small_base_oversized() {
    //     let b = UnsignedInteger::from_string_leaky("105".to_string(), 10, 1024);
    //     let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     let res = b.pow_mod(&e, &m);

    //     let expected = UnsignedInteger::from_string_leaky("93381698043531945590460734835437626929406390544089092303961497613088223192062266567807404255983003371786424645697784253062005750244340967243067126193405796382070980127325598311265307429963380264226672935938163271489566200721235534991781171263956580735259196276780705026850011214281556290838394235159210861122".to_string(), 10, 1024);
    //     assert_eq!(res, expected);
    // }

    // #[test]
    // fn test_powmod_small_exponent() {
    //     let b = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    //     let e = UnsignedInteger::from_string_leaky("105".to_string(), 10, 7);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     let res = b.pow_mod(&e, &m);

    //     let expected = UnsignedInteger::from_string_leaky("75449268817968422679819900589734348654486644392551728445064418436053449491480437746932914650717830240874061893534937751643365068436165993034818308531811356620889371580247889632561792360083344802209721380578912179116118493677119654295291184624591629851342172735975592027041999972633543293770666292467255672690".to_string(), 10, 1024);
    //     assert_eq!(res, expected);
    // }

    // #[test]
    // fn test_powmod_mini() {
    //     let b = UnsignedInteger::from(3u64);
    //     let e = UnsignedInteger::from(7u64);
    //     let m = UnsignedInteger::from(11u64);

    //     let res = b.pow_mod(&e, &m);

    //     let expected = UnsignedInteger::from_string_leaky("9".to_string(), 10, 1024);
    //     assert_eq!(res, expected);
    // }

    // #[test]
    // fn test_powmod_mini_plusmod() {
    //     let b = UnsignedInteger::from(14u64);
    //     let e = UnsignedInteger::from(7u64);
    //     let m = UnsignedInteger::from(11u64);

    //     let res = b.pow_mod(&e, &m);

    //     let expected = UnsignedInteger::from_string_leaky("9".to_string(), 10, 1024);
    //     assert_eq!(res, expected);
    // }
}
