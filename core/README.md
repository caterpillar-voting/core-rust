# README

This is the documentation of the library.

## Public-key Encryption

Public-key encryption allows encryption under a public key. The resulting ciphertext can then only be decrypted using the secret key. Only the secret key needs to be kept secret, the public key can be published.

Here is an example of encryption and decryption.

```rust
type Curve = RistrettoGroup;
use crate::primitives::encryption::Encryption;

#[test]
fn encryption() {
    let mut rng = thread_rng();
    let message = Curve::point_random(&mut rng);

    let encryption = Encryption::<Curve>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

    assert_eq!(message_recovered, Some(message));
}
```

You'll notice that the encryption operates on points on the curve. The plaintext therefore needs to first be encoded to a point. If your plaintext is a number, you can use the `ScalarEncoder` to encode it to a point. Note that you need to provide the expected plaintext range.

```rust
type Curve = RistrettoGroup;
use crate::foundation::encoder::ScalarEncoder;

fn encoding_decoding() {
    // define the encoder with the expected plaintext range of length 2, i.e., (0..1)
    let encoder = ScalarEncoder::<Curve>::new((Scalar::from(0u8), 2));

    // encoding
    let plaintext = Scalar::from(1u8);
    let message = encoder.encode(&plaintext);

    // decoding
    let plaintext_recovered = encoder.decode(&message);
}
````


### Advanced Usage


> [!NOTE]
> The encryption is based on ElGamal, which is (only) IND-CPA secure. ElGamal is therefore malleable (i.e., the ciphertext can be operated on without knowing the secret key), which is necessary for some of the advanced cryptography used in electronic voting, but can be dangerous when not used carefully.
Therefore, the encryption used here is ELGamal augmented with a HTDH2 zero-knowledge proof (ZKP). The augmented scheme is IND-CCA2, and therefore non-malleable.




Points of interest:
- The encryption operates on points on the curve, hence the plaintext needs to first be encoded to a point.
- The encryption includes a HTDH2 ZKP to prevent malleability (transparent to the user). You can override the label and generator of HTDH2 with `Encryption::new()`. 
- The `secret_key` is marked as `ZeroizeOnDrop`.
- You can also use the homomorphic and reencryption properties of ElGamal by using the lower-level API (see below)

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn homomorphic_encrypt_and_decrypt() {
    let mut rng = thread_rng();
    let message = Scalar::from(1u8);

    let el_gamal = ExponentialElGamal::<Curve>::default();
    let secret_key = el_gamal.0.generate_secret_key(&mut rng);
    let public_key = el_gamal.0.derive_public_key(&secret_key);

    let ciphertext = el_gamal.encrypt(&public_key, &Curve::scalar_random(&mut rng), &message);
    let ciphertext_reencrypted = el_gamal.0.reencrypt(&public_key, &Curve::scalar_random(&mut rng), &ciphertext);
    let ciphertext_aggregated = (ciphertext_reencrypted.0 + ciphertext.0, ciphertext_reencrypted.1 + ciphertext.1);

    let message_decoder = BruteForceDiscreteLog::<Curve>::new(Scalar::from(2u8), None);
    let decoded = el_gamal.decrypt(&secret_key, &ciphertext_aggregated, &message_decoder);

    assert_eq!(decoded, Some(Scalar::from(2u8)));
}
```

Points of interest:
- The `ExponentialElGamal` operates on scalars instead of points, and is a wrapper around `ElGamal`.
- `ElGamal` ciphertext can be re-encrypted, and aggregated. In case of `ExponentialElGamal`, the aggregated ciphertext represents the sum of the original messages.
- You need to pass a `decoder` to the `decrypt` function to recover the scalar (the decoder logically performs the discrete log).
