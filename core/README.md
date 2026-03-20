# Core

## Curve

TODO:
- Move to wrapper types?

## Commitment

Implementation of commitment as pedersen.

TODO:
- Create VerifiableGenerator trait (or similar) for the generators.
- Add factor that constructs commitment with sensible parameters

```rust
let mut rng = seeded_rng();

let point = Curve::point_random(&mut rng);
let generators = vec![
    Curve::point_random(&mut rng),
    Curve::point_random(&mut rng),
    Curve::point_random(&mut rng),
];

let messages = vec![
    Message::<Curve> { inner: Scalar::from(10u64) },
    Message::<Curve> { inner: Scalar::from(20u64) },
    Message::<Curve> { inner: Scalar::from(30u64) },
];

let mut hiding = HidingCommitment::new(point, generators, &mut rng);
let (commitment, randomness) = hiding.commit(&messages);

assert!(hiding.verify(&messages, &commitment, &randomness));
```


## Encryption

Implementation of encryption as ElGamal; and homomorphic encryption as Exponential ElGamal.

TODO:
- Support multiple messages for single ElGamal (to be consistent to Pedersen)
- Fully support homomorphic encryption with operators (-, +, +=, -=)
- Implement encoding of bytes to curve (for plain ElGamal to be useful)
- Provide support for multi-recipient ElGamal?