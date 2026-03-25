# Core

## Commitment

Implementation of commitment with pedersen.

```rust
use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;
use crate::primitives::commitment::{HidingCommitment, Message};
use rand::thread_rng;
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn commitment() {
    let mut rng = thread_rng();

    let hiding_commitment = HidingCommitment::<Curve>::new();

    let messages = [Message::<Curve>::new(Scalar::from(2u8))];
    let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages);

    assert!(hiding_commitment.verify(&messages, &commitment, &randomness));
}
```

## Encryption

Implementation of encryption with ElGamal; and homomorphic encryption with Exponential ElGamal.

```rust
use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;
use crate::primitives::encryption::{Encryption, Message};
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn encryption() {
    let mut rng = thread_rng();
    let message = Message::new(Curve::point_random(&mut rng));

    let mut encryption = Encryption::<Curve>::new();
    let secret_key = encryption.generate_secret_key(&mut rng);
    let public_key = encryption.derive_public_key(&secret_key);

    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

    assert_eq!(message_recovered, message);
}
```

```rust
use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;
use crate::primitives::encryption::{HomomorphicEncryption, HomomorphicMessage, HomomorphicMessageRange,};
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn homomorphic_encryption() {
    let mut rng = thread_rng();
    let message = HomomorphicMessage::new(Scalar::from(2u8));
    let message_sum = &message + &message;
    let message_range = HomomorphicMessageRange::new(Scalar::from(4u8), Scalar::from(4u8));

    let mut encryption = HomomorphicEncryption::<Curve>::new();
    let secret_key = encryption.generate_secret_key(&mut rng);
    let public_key = encryption.derive_public_key(&secret_key);

    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let ciphertext_sum = &ciphertext + &ciphertext;
    let message_recovered = encryption.decrypt(&secret_key, &ciphertext_sum, &message_range);

    assert_eq!(message_recovered, Some(message_sum));
}
```

TODO:
- fully test homomorphism of messages / ciphertexts
- add ZKP for CCA2
- encoding of plaintext to messages (i.e., numbers to group points)
- serialization and deserialization of ciphertexts, public keys, private keys and messages
- when decrypting using randomness, check validity of r using alpha?