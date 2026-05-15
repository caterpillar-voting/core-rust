# Core

## Commitment

A (homomorphic) commitment based on Pedersen. 

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn commitment() {
    let mut rng = thread_rng();

    let commitment = Commitment::<Curve>::default();

    let messages = [Scalar::from(2u8)];
    let (commit, opening) = commitment.commit(&mut rng, &messages);

    assert!(commitment.open(&messages, &commit, &opening));
}
```

Points of interest:
- The commitment is `N`-way commitment, with the default being `N=1`.
- The generators are picked verifiably. You can override them with `Commitment::new()`.
- The `opening` is marked as `ZeroizeOnDrop`, as it is the secret that can open the commitment.


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

    assert_eq!(message_recovered, Some(message));
}
```

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

## Zero Knowledge Proofs

Implementation of an interactive Zero Knowledge Proof.

```rust
type Curve = RistrettoGroup;
type Scalar = <RistrettoGroup as Group>::Scalar;

#[test]
fn zk_proof() {
    let mut rng = thread_rng();
    let message = Curve::point_random(&mut rng);

    let el_gamal = ElGamal::<Curve>::default();
    let secret_key = el_gamal.generate_secret_key(&mut rng);
    let public_key = el_gamal.derive_public_key(&secret_key);

    let ciphertext = el_gamal.encrypt(&public_key, &Curve::scalar_random(&mut rng), &message);
    let randomness = Curve::scalar_random(&mut rng);
    let ciphertext_dash = el_gamal.reencrypt(&public_key, &randomness, &ciphertext);

    let claim = ReEncProofBuilder::build_claim::<Curve>(public_key, ciphertext, ciphertext_dash);
    let zk_proof = ZKProof { claim };
    
    let knowledge = ReEncProofBuilder::build_knowledge::<Curve>(Some(randomness));
    let secret_knowledge = SecretKnowledge(knowledge);
    
    let proof_preparation = zk_proof.commit(&mut rng, &secret_knowledge);
    let c = Curve::scalar_random(&mut rng);
    let proof = zk_proof.response(&mut rng, &proof_preparation, &secret_knowledge, &c);

    assert!(zk_proof.verify(&proof, &c))
}
```

Points of interest:
- As we need the randomness used in the re-encryption to form the ZKP, we use the low-level API directly via `el_gamal.reencrypt`
- We use the previded ElGamal `ReEncProofBuilder` that is able to build the re-encryption statements & knowledge.
- The `SecretKnowledge` is marked as `ZeroizeOnDrop`.
- We derive `c` randomly here, while in a real execution this value is received by the verifier
- This interactive proof can also be transformed into a non-interactive proof, see the next example

```rust
#[test]
fn nizk_proof() {
    let mut rng = thread_rng();
    let message1 = Curve::point_random(&mut rng);
    let message2 = Curve::point_random(&mut rng);

    let el_gamal = ElGamal::<Curve>::default();
    let secret_key = el_gamal.generate_secret_key(&mut rng);
    let public_key = el_gamal.derive_public_key(&secret_key);

    let randomness = Curve::scalar_random(&mut rng);
    let ciphertext = el_gamal.encrypt(&public_key, &randomness, &message1);

    let claim1 = EncProofBuilder::build_claim::<Curve>(public_key, ciphertext, message1);
    let claim2 = EncProofBuilder::build_claim::<Curve>(public_key, ciphertext, message2);
    let claim: Claim<Curve> = Or(vec![claim1, claim2]);

    let context_hash = VectorContextHash::new(b"Example".into());
    let nizkp = NIZKProof::new(claim, context_hash);

    let knowledge1 = ReEncProofBuilder::build_knowledge::<Curve>(Some(randomness));
    let knowledge2 = ReEncProofBuilder::build_knowledge::<Curve>(None);
    let knowledge: Knowledge<Curve> = Or(vec![knowledge1, knowledge2]);
    let proof = nizkp.prove(&mut rng, &SecretKnowledge(knowledge));

    assert!(nizkp.verify(&proof))
}
```

Points of interest:
- We compose claims into a proof tree; here we claim encryption towards `message1` or `message2`.
- The non-interace proof needs a hash function. We use the default implementation `VectorContextHash`, which we prefix with `Example`.
- When composing the knowledge, note that we only have a witness for the first statement `Some(randomness)`, as indeed the second statement is false.

## Future steps

features:
- add encoding of plaintext to EncodedMessage (i.e., numbers to group points)
- serialization and deserialization of ciphertexts, public keys, private keys and messages

technical:
- when to implement which default traits? is there any harm in doing so?
