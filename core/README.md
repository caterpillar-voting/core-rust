# README

This is the documentation of the library.

> [!NOTE]
> So far, only encryption is documented, to collect feedback to the style of the documentation.


## Public-key Encryption

Public-key encryption allows encryption under a public key. The resulting ciphertext can then only be decrypted using the secret key. While the public key can be published, typically sent to the end-user to enable them to encrypt, the secret key needs to be kept secret.

Here is an example of encryption and decryption.

```rust
type G = RistrettoGroup;
use crate::primitives::encryption::Encryption;

#[test]
fn encryption() {
    let mut rng = thread_rng();
    let message = G::point_random(&mut rng);

    // create the encryption scheme
    let encryption = Encryption::<G>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    // encrypt and decrypt
    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

    assert_eq!(message_recovered, Some(message));
}
```

You'll notice that the encryption operates on the group `G`. The plaintext therefore needs to first be encoded into an element of `G`. If your plaintext is a number, you can use the `ScalarMessageEncoder`. Note that you need to provide the expected plaintext range, else the decoding will fail.

```rust
type G = RistrettoGroup;
use crate::foundation::encoder::ScalarEncoder;

fn encoding_decoding() {
    // define the encoder with the expected plaintext range of length 2, i.e., (0..1)
    let encoder = ScalarEncoder::<G>::new((Scalar::from(0u8), 2));

    // encoding
    let plaintext = Scalar::from(1u8);
    let message = encoder.encode(&plaintext);

    // decoding
    let plaintext_recovered = encoder.decode(&message);
    
    assert_eq!(plaintext_recovered, Some(plaintext));
}
````

When you use the encryption in your protocol, make sure to configure it properly:
- Choose a `label` that uniquely identifies where this ciphertext is used. This ensures that the ciphertext cannot be used for other purposes, which could break the security of the protocol.
- You may also configure the underlying `ElGamal` scheme, and set the generator `g0` of the HTDH2 ZKP. Only change this default configuration if you understand the implications. The `g0` generator MUST be verifiably independent of the generator used for ElGamal. 


```rust
type G = RistrettoGroup;
use crate::primitives::encryption::Encryption;

fn configure_encryption() {
    let encryption = Encryption::<G> {
        label: b"ElGamal".to_vec(),
        el_gamal: ElGamal::default(),
        g0: G::independent_generators::<1>(b"HTDH2ZKP")[0],
    };
}
```

> [!NOTE]
> The encryption is based on ElGamal, which is (only) IND-CPA secure. ElGamal is therefore malleable (i.e., the ciphertext can be operated on without knowing the secret key)
> This is necessary for some of the advanced cryptography used in electronic voting, but can be dangerous when not used carefully.
> Therefore, the encryption augments ELGamal with a HTDH2 zero-knowledge proof (ZKP).
> This augmented scheme is IND-CCA2 secure, and therefore notably non-malleable. Its security is based on that the generator used by ElGamal is independent of the generator g0 used by the ZKP.


### Advanced Usage

> [!CAUTION]
> Use the lower-level API described here only when you understand the implications.

You can use the lower-level API to perform advanced operations. For example, if you use directly the underlying `ElGamal` scheme, you can perform re-encryption or decrypt using the randomness.

```rust
type G = RistrettoGroup;
use crate::primitives::encryption::el_gamal::ElGamal;

#[test]
fn elgamal_malleability() {
    let mut rng = thread_rng();
    
    let el_gamal = ElGamal::<G>::default();
    let sk = el_gamal.generate_secret_key(&mut rng);
    let pk = el_gamal.derive_public_key(&sk);

    let m = G::point_random(&mut rng);
    let r = G::scalar_random(&mut rng);
    let ciphertext = el_gamal.encrypt(&pk, &r, &m);

    // re-encrypt
    let r_2 = G::scalar_random(&mut rng);
    let ciphertext_2 = el_gamal.reencrypt(&pk, &r_2, &ciphertext);

    // decrypt using randomness
    let m_recovered = el_gamal.decrypt_randomness(&pk, &(r_2 + r), &ciphertext_2);

    assert_eq!(m_recovered, m);
}
```

You may also use the `ExponentialElGamal` scheme, and use the additive homomorphic properties of the scheme. `ExponentialElGamal` is a wrapper around `ElGamal`, and you can access the ELGamal instance at position `0`. 

```rust
type G = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;
use crate::primitives::encryption::el_gamal::ExponentialElGamal;
use crate::foundation::discrete_log::BruteForceDiscreteLog;

#[test]
fn exponential_elgamal_homomorphism() {
    let mut rng = thread_rng();
    let exponential_el_gamal = ExponentialElGamal::<G>::default();

    let sk = exponential_el_gamal.0.generate_secret_key(&mut rng);
    let pk = exponential_el_gamal.0.derive_public_key(&sk);
    let r = G::scalar_random(&mut rng);
    let m = Scalar::from(1u8);

    let ciphertext = exponential_el_gamal.encrypt(&pk, &r, &m);
    let ciphertext_aggregated = (ciphertext.0 + ciphertext.0, ciphertext.1 + ciphertext.1);

    let decoder = BruteForceDiscreteLog::new(m, None);
    let m_decrypted = exponential_el_gamal.decrypt(&sk, &ciphertext_aggregated, &decoder);

    assert_eq!(m_decrypted, Some(Scalar::from(2u8)));
}
```

Note that for decryption, you need to provide a `decoder` that performs the discrete logarithm to recover the plaintext. Besides `BruteForceDiscreteLog`, we also provide `PrecomputedDiscreteLog` which precomputes the values within a given range.

```rust
type G = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;
use crate::foundation::discrete_log::PrecomputedDiscreteLog;

#[test]
fn discrete_logarithm() {
    let range_start = Scalar::from(1u8);
    let log = PrecomputedDiscreteLog::<Curve>::new((range_start, 10), Curve::basepoint());
    
    let encoded = Curve::basepoint() * Scalar::from(3u8);
    let decoded = log.log(&Curve::basepoint(), &encoded);
    
    assert_eq!(decoded, Some(Scalar::from(3u8)));
}
```
