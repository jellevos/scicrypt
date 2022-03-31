**_WARNING: WHILE THIS LIBRARY MAKES SOME EFFORT FOR SECURE IMPLEMENTATIONS, IT SHOULD NOT BE USED FOR ANY PRACTICAL APPLICATIONS. THE CODE IS NOT AUDITED. WE MAKE NO GUARANTEES ABOUT THE CODE'S CORRECTNESS NOR SECURITY._**

Lightweight cryptographic building blocks for proof of concept implementations in applied
cryptography.

While many libraries implementing cryptographic building blocks exist, many fall in one of two
categories:
- Fast but rigid, like many written in C++
- Slow but flexible, like many written in python

This library attempts to find a balance between speed and flexibility, to ease the process of
implementing proof of concepts of cryptographic protocols, such as those in the field of multi-
party computation (MPC).

# Current features
Currently, the library implements the following homomorphic cryptosystems and the associated homomorphic
operations:
- ElGamal over Curve25519 (Ristretto-encoded) and two threshold versions
- ElGamal over safe prime groups and two threshold versions
- Paillier and threshold Paillier
- RSA

In addition, the library implements safe prime generation, which is faster than the same functionality implemented in
other crates. The code is benchmarked between every version to ensure we do not increase run time and to compare against
other implementations.

Check the table below for an average run time comparison (in milliseconds) for safe prime generation:
<table>
    <tr><td><b>Crate | Number of bits</b></td><td><b>128</b></td><td><b>192</b></td><td><b>256</b></td><td><b>320</b></td><td><b>384</b></td></tr>
    <tr><td>glass_pumpkin</td><td>52.5</td><td>170</td><td>402</td><td>652</td><td>1530</td></tr>
    <tr><td>openssl</td><td>3.95</td><td>11.1</td><td>21.9</td><td>53.6</td><td>79.8</td></tr>
    <tr><td>scicrypt</td><td>2.20</td><td>7.02</td><td>20.1</td><td>37.5</td><td>72.5</td></tr>
</table>

**Updated: 31 Mar 2022 from [GitHub Actions](https://github.com/jellevos/scicrypt/runs/5433877697)**

You can run this benchmark yourself by executing `cargo bench --bench prime_gen`. By default, this benchmark is turned off because it can take up to 15 minutes to run. In other words, it will not run when you simply run `cargo bench`. _Note that on my personal laptop, OpenSSL slightly outperforms scicrypt on average, so results can differ based on hardware._

# Upcoming features
These are the upcoming minor versions and the functionality they will add.

## Ease of use update
<table>
    <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
    <tr><td>Encoding signed ints</td> <td></td></tr>
    <tr><td>Discrete log lookup tables</td><td> </td></tr>
    <tr><td>Debugging tools</td><td> </td></tr>
</table>

## Secret sharing update
<table>
    <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
    <tr><td>Additive secret sharing</td> <td></td></tr>
    <tr><td>Multiplicative secret sharing</td><td> </td></tr>
    <tr><td>Shamir's secret sharing</td><td> </td></tr>
</table>

## Oblivious transfer update
<table>
    <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
    <tr><td>OT & extensions</td> <td></td></tr>
    <tr><td>OPRF</td><td> </td></tr>
    <tr><td>OPPRF</td><td> </td></tr>
</table>

## RLWE-based encryption
<table>
    <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
    <tr><td>Polynomial arithmetic</td> <td></td></tr>
    <tr><td>BGV (no bootstrapping)</td><td> </td></tr>
</table>
