# Develop

We describe the API design of the library.

There are two intended target public for this library:
- cryptographers who want to review the code, or implement new primitives based on it.
- end-users who want to use the library safely.

Therefore, we provide two kind of APIs:
- a low-level API with direct access to the implemented primitives, with usability (and safety) coming second.
- a high-level API that by design helps to make using the library safe. In turn, the functionality is heavily constrained.

In this spirit, this API has been drafted.


## Low-level API

The low-level API provides direct access to the primitives, to enable reusability and extensibility. 

General:
- There are no safeguards or wrappers that shield against improper usage.
- The naming and structure is close to what a cryptographer would expect (e.g., we use the variable names from the specification/paper).
- We do not provide dedicated functions for functionality that is trivial to implement oneself (e.g., homomorphism for ElGamal encryption).

The code resides in the submodules, e.g., `primitives/encryption/el_gamal.rs`.


## High-level API

The high-level API shields implementation details from the user, and instead gives semantic wrappers to all data structures.

General:
- Secrets (e.g., private keys) are wrapped and annotated with ZeroOnDrop. All data types are given a semantic meaning, but no unnecessary wrappers (e.g., the `PublicKey` is just a type alias to `Point`).
- Primitives are semantic wrappers possibly encapsulating multiple algorithms, e.g., the `Encryption` wraps ElGamal with HTDH2. They can be constructed without arguments with sensible defaults (e.g., `Encryption::default()`).
- Functionality that is difficult to get right is not exposed (e.g., decryption using the randomness for ElGamal).

The code resides in the modules, e.g., `primitives/encryption.rs`.


## Future steps

primitives:
- refactor randomness crates or document justification
- add commitment that uses hash; possibly as default hash (but is wrapper useful?); possibly remove high-level hash altogether
- clear up whether to reuse g0 of HTDH2 or not
- refactor documentation to reflect the newest state

protocols:
- Shuffle (Groth05; MultiRecipient; Rerandomization-Mixnet) -> sample implementation already exists
- DKG (ElectionGuard probably, maybe Belenios)
- PET (https://dl.acm.org/doi/10.1007/978-3-030-59013-0_2) -> sample implementation already exists

interface:
- serialization and deserialization of ciphertexts, public keys, private keys and messages
- provide in JS high-level API (see [../core-wasm](core-wasm))
- provide in CLI high-level API

minor technical:
- when to implement which default traits? is there any harm in doing so?
- add convenience Add/Mul; also MultiAdd (in particular, for M-R-ElGamal); but does this not hide important details about allocation/copy/clone?
- mul by basepoint separate overload for optimizations; use separate type? use if/else in mul overload?
- Remove Clone/Default in group; or can group/point/scalar architecture to avoid this ugly clone?
- get_challenge required to be stateless (in contrast to ScalarMessageEncoder.decoder); is this a problem?

