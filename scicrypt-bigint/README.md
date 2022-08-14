_This is a part of **scicrypt**. For more information, head to the
[scicrypt](https://crates.io/crates/scicrypt) crate homepage._

This crate implements a `BigInteger`, for which most arithmetic operations take a constant amount of time given the specified sizes.

Exceptions:
- Initializing from strings using `from_string`
- Equality checks (`PartialEq`)
- Computing `lcm` 
