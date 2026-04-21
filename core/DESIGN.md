# Design

Here we describe the API design of the library.

There are two major target public for this library:
- cryptographers that want to review the code, or implement new primitives based on it.
- end-users that want to use the library, but do not implement new functionality

We address both target public by providing two different APIs:
- a low-level API that gives direct access to the implemented primitives. This is a loaded shotgun, and it is pointed at your foot. 
- a high-level API that prevents access low-level primitives, but by design helps to make using the library safe.

In this spirit, this API has been drafted. Here, we document the detailed intentional design decisions. 

## Low-level API

the low-level API provides direct access to the primitives. there are no safeguards or wrappers that shield against improper usage. in turn, it should be easy to extend upon it to construct new primitives.

general:
- use math naming for variables (hence short, as in spec)

foundation/group:
- we introduce the group abstraction to support multiple possible groups.
- the group does not wrap its implementation (i.e., it is just an implemented trait), as this is a low-level API
- we implement the serialization directly on the point/scalar with `to_bytes` and `from_bytes` to have no doubt about the serialization format used. we accept the name collision notably in ristretto with existing to_bytes and from_bytes functions.
- assumption that underlying group are elliptic curves, hence use naming of Points/Scalars. finite fields are not a target at the moment.

primitives/encryption/*:
- ElGamal / ExponentialElGamal in the same file to reuse code without exposing implementation details (i.e., without making g public on ElGamal or introducing a new field for it in ExponentialElGamal)
- No multi-message API because this would simply be a list of ElGamal ciphertext.
- Homomorphism has no direct implementation at this API level (trivial to do self).

primitives/commitment/*:
- assert that checks number of messages is lower/equal to available generators as otherwise a bug.

## High-level API

the high-level API shields implementation details from the user, and instead gives semantic wrappers to all data structures. 

general:
- secret values: secret keys or randomness (pedersen) are wrapped and annotated with ZeroOnDrop
- validation: done at compile time, unless type system not expressive enough
- naming: add core functionality in name (e.g., `HomomorphicEncryption`)
- naming: add property prefix if needed to disambiguate with representation names (e.g., prefix `H` for hiding to `HHomomorphicCommittment` because needs to return `HomomorphicCommitment`)

primitives/encryption/*:
- Do not expose decryption using randomness; this is an advanced scenario not need for the normal user
- Explicitly allow homomorphically adding ciphertext by overriding + and - operators

primitives/commitment/*:
- include the number of generators in the type to avoid misuse
