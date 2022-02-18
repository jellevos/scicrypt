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

Check the table below for a run time comparison (in milliseconds) for safe prime generation:
<table>
    <tr><td><b>Crate | Number of bits</b></td><td><b>128</b></td><td><b>192</b></td><td><b>256</b></td><td><b>320</b></td><td><b>384</b></td></tr>
    <tr><td>glass_pumpkin</td> <td>52.160</td><td>157.70</td><td>319.03</td><td>772.41</td><td>1328.3</td></tr>
    <tr><td>scicrypt</td><td>12.609</td><td>53.627</td><td>150.05</td><td>321.11</td><td>468.07</td></tr>
</table>

**Updated: 10 Aug 2021 by GitHub Actions**

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
