# Contribute

You are very welcome to contribute!

Current open tasks:
- Implementation of cryptography: [core/DEVELOP.md](DEVELOP.md of core).
- Integrating it as wasm in the browser: [core-wasm](core-wasm crate). But it might make sense to first tackle the core improvements.
- You are free to propose your own task.

Before starting a new task, please open an issue to discuss the scope and target of the task. 
If you implement cryptography, at least two people need to be able to fully understand both the math behind it and the code.


## Development strategy

Version v0.1:
- Add all major primitives and protocols in `core`. 
- Make the code runnable in the browser through `core-wasm`.
- Accepted Limitation 1: A single implementation per primitive or protocol (e.g., only a single mixnet) is sufficient.
- Accepted Limitation 2: The API needs not to be fixed: Priorize speed of development over perfection.

Version v0.2:
- Based on the "full picture" granted by v0.1, refactor APIs where necessary.
- Try out the code in practice in real voting software. After this experience, consider refactoring again (to release v0.3, or go for v1.0)
- Accepted Limitation: A single implementation per primitive or protocol (e.g., only a single mixnet) is sufficient.

Version v1.0:
- End-user documentation of the API.
- Write the specification.

