//! Tracked numbers ("tnums"): the known-bits abstract domain used by the
//! verifier, mirroring the Linux kernel's `kernel/bpf/tnum.c`.
//!
//! A tnum `(value, mask)` represents every 64-bit number `n` such that
//! `n & !mask == value`. Bits set in `mask` are unknown; bits clear in `mask`
//! are known and given by `value`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}

pub const UNKNOWN: Tnum = Tnum {
    value: 0,
    mask: u64::MAX,
};

#[allow(clippy::should_implement_trait)] // kernel-style tnum op names
impl Tnum {
    #[inline]
    pub fn const_val(v: u64) -> Tnum {
        Tnum { value: v, mask: 0 }
    }

    #[inline]
    pub fn unknown() -> Tnum {
        UNKNOWN
    }

    /// Smallest tnum containing every value in `[min, max]`.
    pub fn range(min: u64, max: u64) -> Tnum {
        let chi = min ^ max;
        let bits = 64 - chi.leading_zeros() as u64;
        if bits > 63 {
            return UNKNOWN;
        }
        let delta = (1u64 << bits) - 1;
        Tnum {
            value: min & !delta,
            mask: delta,
        }
    }

    #[inline]
    pub fn is_const(&self) -> bool {
        self.mask == 0
    }

    /// Is `self` a refinement of (contained in) `other`?
    #[inline]
    pub fn is_subset_of(&self, other: &Tnum) -> bool {
        // every unknown bit of self must be unknown in other, and known bits
        // must agree where other knows them
        (self.mask & !other.mask) == 0 && (self.value & !other.mask) == (other.value & !other.mask)
    }

    /// Could `self` equal the constant `v`?
    #[inline]
    pub fn contains(&self, v: u64) -> bool {
        (v & !self.mask) == self.value
    }

    /// Minimum possible value.
    #[inline]
    pub fn umin(&self) -> u64 {
        self.value
    }
    /// Maximum possible value.
    #[inline]
    pub fn umax(&self) -> u64 {
        self.value | self.mask
    }

    pub fn lshift(self, shift: u8) -> Tnum {
        Tnum {
            value: self.value << shift,
            mask: self.mask << shift,
        }
    }

    pub fn rshift(self, shift: u8) -> Tnum {
        Tnum {
            value: self.value >> shift,
            mask: self.mask >> shift,
        }
    }

    /// Arithmetic right shift of a tnum truncated to `insn_bitness` first.
    pub fn arshift(self, shift: u8, insn_bitness: u8) -> Tnum {
        if insn_bitness == 32 {
            Tnum {
                value: ((self.value as u32 as i32) >> shift) as u32 as u64,
                mask: ((self.mask as u32 as i32) >> shift) as u32 as u64,
            }
        } else {
            Tnum {
                value: ((self.value as i64) >> shift) as u64,
                mask: ((self.mask as i64) >> shift) as u64,
            }
        }
    }

    pub fn add(self, b: Tnum) -> Tnum {
        let sm = self.mask.wrapping_add(b.mask);
        let sv = self.value.wrapping_add(b.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | b.mask;
        Tnum {
            value: sv & !mu,
            mask: mu,
        }
    }

    pub fn sub(self, b: Tnum) -> Tnum {
        let dv = self.value.wrapping_sub(b.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(b.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | b.mask;
        Tnum {
            value: dv & !mu,
            mask: mu,
        }
    }

    pub fn and(self, b: Tnum) -> Tnum {
        let alpha = self.value | self.mask;
        let beta = b.value | b.mask;
        let v = self.value & b.value;
        Tnum {
            value: v,
            mask: alpha & beta & !v,
        }
    }

    pub fn or(self, b: Tnum) -> Tnum {
        let v = self.value | b.value;
        let mu = self.mask | b.mask;
        Tnum {
            value: v,
            mask: mu & !v,
        }
    }

    pub fn xor(self, b: Tnum) -> Tnum {
        let v = self.value ^ b.value;
        let mu = self.mask | b.mask;
        Tnum {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Kernel `tnum_mul`: value*value plus accumulated uncertainty terms.
    pub fn mul(self, b: Tnum) -> Tnum {
        let mut a = self;
        let mut b = b;
        let acc_v = a.value.wrapping_mul(b.value);
        let mut acc_m = Tnum { value: 0, mask: 0 };
        while a.value != 0 || a.mask != 0 {
            if a.value & 1 != 0 {
                acc_m = acc_m.add(Tnum {
                    value: 0,
                    mask: b.mask,
                });
            } else if a.mask & 1 != 0 {
                acc_m = acc_m.add(Tnum {
                    value: 0,
                    mask: b.value | b.mask,
                });
            }
            a = a.rshift(1);
            b = b.lshift(1);
        }
        Tnum {
            value: acc_v,
            mask: 0,
        }
        .add(acc_m)
    }

    /// Intersection: keep only information consistent with both.
    /// (Kernel `tnum_intersect`; caller must know the tnums actually overlap.)
    pub fn intersect(self, b: Tnum) -> Tnum {
        let v = self.value | b.value;
        let mu = self.mask & b.mask;
        Tnum {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Union: weakest tnum containing both.
    pub fn union(self, b: Tnum) -> Tnum {
        let chi = self.value ^ b.value;
        let mu = self.mask | b.mask | chi;
        Tnum {
            value: self.value & !mu,
            mask: mu,
        }
    }

    /// Truncate to the low `size` bytes (zero-extend).
    pub fn cast(self, size: u8) -> Tnum {
        if size == 8 {
            return self;
        }
        let keep = (1u64 << (size * 8)) - 1;
        Tnum {
            value: self.value & keep,
            mask: self.mask & keep,
        }
    }

    /// The subrange of this tnum's low 32 bits, as a 32-bit tnum.
    pub fn subreg(self) -> Tnum {
        self.cast(4)
    }
}

impl core::fmt::Display for Tnum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_const() {
            write!(f, "{:#x}", self.value)
        } else if *self == UNKNOWN {
            write!(f, "unknown")
        } else {
            write!(f, "(v={:#x} m={:#x})", self.value, self.mask)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tnum_add_consts() {
        let a = Tnum::const_val(3).add(Tnum::const_val(4));
        assert_eq!(a, Tnum::const_val(7));
    }

    #[test]
    fn tnum_and_masks_bits() {
        // unknown & 0xff -> low byte unknown, rest zero
        let a = UNKNOWN.and(Tnum::const_val(0xff));
        assert_eq!(a.value, 0);
        assert_eq!(a.mask, 0xff);
        assert_eq!(a.umax(), 0xff);
    }

    #[test]
    fn tnum_range_pow2() {
        let t = Tnum::range(0, 15);
        assert_eq!(t.value, 0);
        assert_eq!(t.mask, 15);
        assert!(t.contains(0) && t.contains(15) && !t.contains(16));
    }

    #[test]
    fn tnum_mul_const() {
        assert_eq!(
            Tnum::const_val(7).mul(Tnum::const_val(6)),
            Tnum::const_val(42)
        );
        // (unknown low byte) * 4 -> low two bits known zero
        let t = Tnum { value: 0, mask: 0xff }.mul(Tnum::const_val(4));
        assert_eq!(t.value & 3, 0);
        assert_eq!(t.mask & 3, 0);
    }

    #[test]
    fn tnum_subset() {
        let big = Tnum { value: 0, mask: 0xff };
        let small = Tnum { value: 0x0f, mask: 0xf0 };
        assert!(small.is_subset_of(&big));
        assert!(!big.is_subset_of(&small));
    }
}
