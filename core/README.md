# Core

## Commitment

A (homomorphic) commitment based on Pedersen. 

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn commitment() {
    let mut rng = thread_rng();

    let homomorphic_commitment = HHomomorphicCommitment::<Curve>::default();

    let messages = [Scalar::from(2u8)];
    let (commitment, opening) = homomorphic_commitment.commit(&mut rng, &messages);

    assert!(homomorphic_commitment.open(&messages, &commitment, &opening));
}
```

Points of interest:
- The commitment is `N`-way commitment, with the default being `N=1`.
- The generators are picked verifiably. You can override them with `HomomorphicCommitment::new()`.
- The `opening` is marked as `ZeroizeOnDrop`, as it is the secret that can open the commitment.
- The commitment is homomorphic, hence you can add both commitments and openings (e.g., `commitment + commitment`)


## Encryption

Encryption based on ElGamal.

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn encryption() {
    let mut rng = thread_rng();
    let message = Curve::point_random(&mut rng);

    let encryption = Encryption::<Curve>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

    assert_eq!(message_recovered, message);
}
```

Points of interest:
- The encryption operates on points on the curve, hence the plaintext needs to first be encoded to a point.
- The `secret_key` is marked as `ZeroizeOnDrop`.
- There is also a homomorphic variant of encryption, see the next example.


```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn homomorphic_encryption() {
    let mut rng = thread_rng();
    let message = Scalar::from(2u8);
    let decoder = GreedyDiscreteLog::new(Scalar::from(4u8), None);

    let encryption = EncryptionHomomorph::<Curve>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let ciphertext_sum = &ciphertext + &ciphertext;
    let message_recovered = encryption.decrypt(&secret_key, &ciphertext_sum, &decoder);

    assert_eq!(message_recovered, Some(&message + &message));
}
```

Points of interest:
- The homomorphic variant encrypts scalars instead of points.
- The `ciphertext` is homomorphic (e.g., `ciphertext + ciphertext` is valid, and then represents `message + message`)
- You need to pass a `decoder` to the `decrypt` function that logically performs the discrete log.


## Zero Knowledge Proofs

Implementation of an interactive Zero Knowledge Proof.

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn zk_proof() {
    let mut rng = thread_rng();
    let message = Curve::point_random(&mut rng);

    let encryption = Encryption::<Curve>::default();
    let (secret_key, public_key) = encryption.key_gen(&mut rng);

    let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
    let randomness = Curve::scalar_random(&mut rng);
    let ciphertext_dash = encryption.el_gamal.reencrypt(&public_key, &randomness, &ciphertext);

    let re_enc = ReEncProofBuilder::<Curve>::new(public_key, ciphertext, ciphertext_dash, Some(randomness));
    let (zk_proof, knowledge) = ZKProof::from_builder(&re_enc);

    let proof_preparation = zk_proof.prepare(&mut rng, &knowledge);
    let c = Curve::scalar_random(&mut rng);
    let proof = zk_proof.finalize(&mut rng, &proof_preparation, &knowledge, &c);

    assert!(zk_proof.check(&proof, &c))
}
```

Points of interest:
- As we need the randomness used in the re-encryption to form the ZKP, we use the low-level API directly via `encryption.el_gamal.reencrypt`
- We use the pre-made ElGamal `ReEncProofBuilder` that is able to build the re-encryption statements.
- We use `ZKProof::from_builder` that constructs the ZKP and the associated knowledge (the secrets) from the builder.
- The `knowledge` is marked as `ZeroizeOnDrop`.
- We prepare the proof, by committing to the true statements (here, the re-encryption statement) and simulating the other statements (here none, but see next example).
- We derive `c` randomly here, while in a real execution this value is received by the verifier
- Finally, we can finalize and check the proof
- This interactive proof can also be transformed into a non-interactive proof, see the next example

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

    let context_hash = VectorContextHash::new(b"Example".into());
    let nizkp = NIZKProof::new(zk_proof, context_hash);
    let proof = nizkp.proof(&mut rng, &knowledge);

    assert!(nizkp.verify(&proof))
}
```

Points of interest:
- We use the pre-made ElGamal `EncProofBuilder` that proves the ciphertext to be an encryption of some specific message.
- We build two statments that claim the `ciphertext` is encryption towards `message1` and `message2`, respectively. We only have knowledge of the witness for the first statement `Some(randomness)`, as indeed the second statement is false.
- We joint the two statements in an `Or` tree, and build are ZKP from it.
- As we use the non-interactive ZKP variant, we need to hash the context. We use the default implementation `VectorContextHash` which we prefix with `Example`.


## Future steps

features:
- add encoding of plaintext to EncodedMessage (i.e., numbers to group points)
- serialization and deserialization of ciphertexts, public keys, private keys and messages

technical:
- when to implement which default traits? is there any harm in doing so?
