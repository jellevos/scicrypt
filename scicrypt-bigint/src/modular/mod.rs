use subtle::{Choice, ConditionallySelectable};

use crate::UnsignedInteger;

use self::rem::reduce;

mod inv;
mod pow;
mod rem;
mod add;
mod mul;

#[derive(Debug, Clone, Copy)]
struct MontgomeryParams<const LIMB_COUNT: usize> {
    modulus: UnsignedInteger<LIMB_COUNT>,
    montgomery_r: UnsignedInteger<LIMB_COUNT>,
    montgomery_r2: UnsignedInteger<LIMB_COUNT>,
    // We only need the LSB because during reduction this value is multiplied modulo 2**64.
    modulus_neg_inv: u64,
}

impl<const LIMB_COUNT: usize> MontgomeryParams<LIMB_COUNT> {
    /// Note that the modulus must be tight (i.e. it should be at least somewhat close in size to `LIMB_COUNT`).
    pub fn new(modulus: UnsignedInteger<LIMB_COUNT>) -> Self {
        let montgomery_r = -modulus;
        let mut montgomery_r2 = reduce(montgomery_r.square(), &modulus);
        let modulus_neg_inv = (montgomery_r - &modulus.invert(&montgomery_r).unwrap()).limbs[0];

        MontgomeryParams {
            modulus,
            montgomery_r,
            montgomery_r2,
            modulus_neg_inv,
        }
    }
}

struct ModularInteger<const LIMB_COUNT: usize> {
    value: UnsignedInteger<LIMB_COUNT>,
    modulus_params: MontgomeryParams<LIMB_COUNT>,
}

impl<const LIMB_COUNT: usize> ModularInteger<LIMB_COUNT> {
    pub fn new(integer: UnsignedInteger<LIMB_COUNT>, modulus_params: MontgomeryParams<LIMB_COUNT>) -> Self {
        // BigInt<2*bits> tmp;
        // tmp.copy(this->val);

        // Fp<bits, p, r, r2, inv>* target;
        // target = reinterpret_cast<Fp<bits, p, r, r2, inv>*>(&integer);

        // const FpBase<bits>* b = reinterpret_cast<const FpBase<bits>*>(&r2);
        // this->FpBase<bits>::multiply(*this, *b, p, inv.words[0]);

        let mut modular_integer = ModularInteger {
            value: integer,
            modulus_params,
        };

        modular_integer *= &modulus_params.montgomery_r2;

        modular_integer
    }

    pub fn retrieve(&self) -> UnsignedInteger<LIMB_COUNT> {
        let product = self.value.multiply(&self.modulus_params.montgomery_r);
        montgomery_reduction(product, &self.modulus_params)
    }
}

/// Algorithm 14.32 in Handbook of Applied Cryptography (https://cacr.uwaterloo.ca/hac/about/chap14.pdf)
fn montgomery_reduction<const LIMB_COUNT: usize>(lower_upper: (UnsignedInteger<LIMB_COUNT>, UnsignedInteger<LIMB_COUNT>), modulus_params: &MontgomeryParams<LIMB_COUNT>) -> UnsignedInteger<LIMB_COUNT> {
    let (mut lower, mut upper) = lower_upper;
    
    let mut meta_carry = 0;
    for i in 0..LIMB_COUNT {
        let u = lower.limbs[i] as u128 * modulus_params.modulus_neg_inv as u128;

        let new_limb = (u * modulus_params.modulus.limbs[0] as u128).wrapping_add(lower.limbs[i] as u128);
        let mut carry = new_limb >> 64;

        for j in 1..(LIMB_COUNT - i) {
            let new_limb = (u * modulus_params.modulus.limbs[i] as u128).wrapping_add(lower.limbs[i + j] as u128).wrapping_add(carry);
            carry = new_limb >> 64;
            lower.limbs[i + j] = new_limb as u64;
        }
        for j in (LIMB_COUNT - i)..LIMB_COUNT {
            let new_limb = (u * modulus_params.modulus.limbs[i] as u128).wrapping_add(upper.limbs[i + j] as u128).wrapping_add(carry);
            carry = new_limb >> 64;
            upper.limbs[i + j] = new_limb as u64;
        }

        let new_sum = (upper.limbs[i] as u128).wrapping_add(carry).wrapping_add(meta_carry);
        meta_carry = new_sum >> 64;
        upper.limbs[i] = new_sum as u64;
    }

    // Division is simply taking the upper half of the limbs
    // Final reduction (at this point, the value is at most 2 * modulus)
    let must_reduce = Choice::from((upper >= modulus_params.modulus) as u8);
    upper -= &UnsignedInteger::conditional_select(&UnsignedInteger::zero(), &modulus_params.modulus, must_reduce);

    upper
}
