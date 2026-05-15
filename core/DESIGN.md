# Design

Here we describe the API design of the library.

There are two major target public for this library:
- cryptographers that want to review the code, or implement new primitives based on it.
- end-users that want to use the library, but do not implement new functionality

We address both target public by providing APIs on different levels:
- a high-level API that by design helps to make using the library safe. In turn, the functionality is heavily constrained.
- a low-level API that gives direct access to the implemented primitives. In turn, the functionality is very versatile, and usability comes second.

In this spirit, this API has been drafted. Here, we document the detailed intentional design decisions. 

## Low-level API

the low-level API provides direct access to the primitives. there are no safeguards or wrappers that shield against improper usage. in turn, it should be easy to extend upon it to construct new primitives.

general:
- use math naming for variables (hence short, as in spec)

foundation/group:
- we introduce the group abstraction to support multiple possible groups.
- the group does not wrap its implementation (i.e., it is just an implemented trait), as this is a low-level API
- we implement the serialization directly on the point/scalar with `to_bytes` and `from_bytes` to have no doubt about the serialization format used. we accept the name collision notably in ristretto with existing to_bytes and from_bytes functions.
- use naming of Points/Scalars (even if finite fields are also supported)

primitives/encryption/*:
- No multi-message API because this would simply be a list of ElGamal ciphertext.
- Homomorphism has no direct implementation at this API level (trivial to do self).

primitives/commitment/*:
- assert that checks number of messages is lower/equal to available generators as otherwise a bug.

## High-level API

the high-level API shields implementation details from the user, and instead gives semantic wrappers to all data structures. 

general:
- secret values: secret keys or randomness (pedersen) are wrapped and annotated with ZeroOnDrop
- wrapper types: only introduce wrapper types to add functionality (e.g., for secret values). else, use a type alias.
- validation: done at compile time, unless type system not expressive enough

primitives/encryption/*:
- directly include ZKP to ensure ciphertext is non-malleable. Consequentially, reencryption or homomorphism is not provided in the API, but this is an advanced scenario that normal users should not touch.
- in the same spirit, decryption using randomness not supported (as encryption randomness used never exposed to user)

primitives/commitment/*:
- include the number of generators in the type to avoid misuse
