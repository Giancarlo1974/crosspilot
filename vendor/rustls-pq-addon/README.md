# rustls-pq-addon: Add postquantum hybrid support to any rustls `CryptoProvider`

This crate uses [`ml_kem`], along with an elliptic curve backend
([`x25519-dalek`], [`p256`] or [`p384`])
to implement the hybrid post-quantum key exchange algorithms from
[draft-ietf-tls-ecdhe-mlkem] for use with [`rustls`].

It is not a full [`CryptoProvider`];
instead, it lets you modify an existing `CryptoProvider`
to add whichever hybrid groups it lacks.

Currently, it is unreviewed and untested.
**Don't use it!**

I have tested that it appears to successfully handshake
with itself, and with openssl.
I've added interoperability tests with the
handshakes implemented in aws_lc.  That's it.

This is written by Nick Mathewson,
who is _not_ a real cryptographer,
and who is not affiliated with rustls.

## Motivation

At present (Feb 2026),
not all rustls `CryptoProviders` have support for the
[draft-ietf-tls-ecdhe-mlkem] key exchange algorithms.
Of the two defaults, only has [`aws_lc_rs`] currently supports these groups.
But for various reasons[^1], you might want to use [`ring`]
or one of the [other `CryptoProviders`] that doesn't have hybrid PQ support.
This crate allows you to do so.

[^1]: Notably, you might want to avoid the license terms of `aws-lc-rs`,
      which still use the [pre-2021 OpenSSL license] with its
      [GPL-incompatible] advertising clause.
      Amazon is aware of the problem,
      but [has not been in a hurry] to address the issue.

As of Feb 2026, the following `CryptoProvider`s
appear to have hybrid PQ handshake support:
  - [`aws_lc_rs`]
  - [`rustls_graviola`]
  - [`rustls-openssl`] (requires Openssl 3.5.0 for PQ.)

## Development plans

I plan to get this crate to the point where we can use it in [`arti`] with
reasonably high confidence in its correctness.  I will likely stop
maintaining this crate if the `ring` provider gets its own implementations of
these key-exchange groups, _or_ if the `rustls-rustcrypto` project ships them
and stops being experimental.

I have no plan to add support for PQ-only handshakes;
please don't ask.

## Feature flags

- `thread_rng`: (default) Provide instantiations of the key exchange groups
  using `rand::rng()` as the underlying CSPRNG.
- `x25519`: (default) Enable the X25519MLKEM768 hybrid key exchange group.
- `p256`: Enable the `SecP256r1MLKEM768` hybrid key exchange group.
- `p384`: Enable the `SecP384r1MLKEM1024` hybrid key exchange group.

## Example usage

The default "ring" provider, as of this writing, does not support
postquantum key exchange.  Here is how you might add it using
this crate:

```
fn install_ring_provider_with_hybrid_pq() {
    let mut provider = rustls::crypto::ring::default_provider();

    // Install every pq hybrid algorithm that's compiled into
    // rustls_pq_addon.  By default, only X25519MLKEM768
    // is compiled in, but you can enable others with this crate's
    // feature flags.
    rustls_pq_addon::prepend_all_groups(&mut provider);

    provider.install_default();
}
```

If you wanted to install only a particular algorithm,
you could do it like this:

```
fn install_ring_provider_with_x25519mlkem768() {
    let mut provider = rustls::crypto::ring::default_provider();

    // Note that we insert the hybrid PQ group at the start of kx_groups,
    // so that it will receive priority.
    provider.kx_groups.insert(0, &rustls_pq_addon::X25519MLKEM768);

    provider.install_default();
}
```

All of the above examples will create ephemeral keys using `rand::rng()`.
This is a reasonably strong and secure cryptographic algorithm,
and there's no reason IMO to worry about it using it.
But if you would rather use the same `SecureRandom` algorithm
as the rest of your rustls provider,
you could do it like this:

```
use std::sync::OnceLock;
fn install_ring_provider_with_x25519mlkem768() {
    use rustls_pq_addon::X25519MlKem768;
    // static instance of the hybrid group.
    static X25519_MLKEM_768: OnceLock<X25519MlKem768>
        = OnceLock::new();

    let mut provider = rustls::crypto::ring::default_provider();

    let group = X25519_MLKEM_768.get_or_init(||
        X25519MlKem768::new(provider.secure_random)
    );

    provider.kx_groups.insert(0, group);

    provider.install_default();
}
```

[`ml_kem`]: https://docs.rs/ml-kem/0.2.3/ml_kem/index.HTML
[`x25519-dalek`]: https://docs.rs/x25519-dalek/latest/x25519_dalek/
[`p256`]: https://docs.rs/p256/latest/p256/
[`p384`]: https://docs.rs/p256/latest/p384/
[draft-ietf-tls-ecdhe-mlkem]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[`rustls`]: https://docs.rs/rustls/latest/rustls/
[`CryptoProvider`]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html
[`aws_lc_rs`]: https://docs.rs/rustls/latest/rustls/crypto/aws_lc_rs/index.html
[`ring`]: https://docs.rs/rustls/latest/rustls/crypto/ring/index.html
[other providers]: https://docs.rs/rustls/latest/rustls/index.html#third-party-providers
[pre-2021 OpenSSL license]: https://openssl-library.org/source/license/index.html
[GPL-incompatible]: https://www.gnu.org/licenses/license-list.html#OriginalBSD
[has not been in a hurry]: https://github.com/aws/aws-lc/issues/2203
[`rustls_graviola`]: https://crates.io/crates/rustls-graviola
[`rustls-openssl`]: https://github.com/RustCrypto/rustls-rustcrypto
[`arti`]: https://arti.torproject.org/
