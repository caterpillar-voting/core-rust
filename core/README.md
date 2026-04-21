# Core

## Commitment

Implementation of commitment with pedersen.

```rust
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

Implementation of encryption with ElGamal.

```rust
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

Implementation of homomorphic encryption with Exponential ElGamal.

```rust
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

## (Non-Interactive) Zero Knowledge Proofs

Implementation of an interactive Zero Knowledge Proof.

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn zk_proof() {
    let mut rng = thread_rng();
    let message1 = Curve::point_random(&mut rng);
    let message2 = Curve::point_random(&mut rng);

    let encryption = Encryption::<Curve>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    let randomness = Curve::scalar_random(&mut rng);
    let ciphertext = encryption.el_gamal.encrypt(&public_key, &randomness, &message1);

    let enc1 = EncProofBuilder::<Curve>::new(public_key, ciphertext, message1, Some(randomness));
    let (zk_proof, knowledge) = ZKProof::from_builder(&enc1);

    let proof_preparation = zk_proof.prepare(&mut rng, &knowledge);
    let c = Curve::scalar_random(&mut rng);
    let proof = zk_proof.finalize(&mut rng, &proof_preparation, &knowledge, &c);

    assert!(zk_proof.check(&proof, &c))
}
```

Implementation of non-interactive Zero Knowledge Proofs.

```rust
#[test]
fn nizk_proof() {
    let mut rng = thread_rng();
    let message1 = Curve::point_random(&mut rng);
    let message2 = Curve::point_random(&mut rng);

    let encryption = Encryption::<Curve>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    let randomness = Curve::scalar_random(&mut rng);
    let ciphertext = encryption.el_gamal.encrypt(&public_key, &randomness, &message1);

    let enc1 = EncProofBuilder::<Curve>::new(public_key, ciphertext, message1, Some(randomness));
    let enc2 = EncProofBuilder::<Curve>::new(public_key, ciphertext, message2, None);
    let tree: TreeProofBuilder<Curve> = Or(vec![Leaf(&enc1), Leaf(&enc2)]);
    let (zk_proof, knowledge) = ZKProof::from_builder(&tree);

    let nizkp = NIZKProof::new(zk_proof, VectorContextHash::default());
    let proof = nizkp.proof(&mut rng, &knowledge);

    assert!(nizkp.verify(&proof))
}

```

## Future steps

features:
- add ZKP for CCA2
- add encoding of plaintext to EncodedMessage (i.e., numbers to group points)
- serialization and deserialization of ciphertexts, public keys, private keys and messages

technical:
- fully test modules (e.g., homomorphism of messages / ciphertexts, invalid ZKP trees)
- when to implement which default traits? is there any harm in doing so?
