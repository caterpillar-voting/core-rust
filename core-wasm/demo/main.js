import init, {
    WasmSecretKey,
    WasmMessage,
} from "./pkg/caterpillar_voting_core_wasm.js";

async function main() {
    await init();

    const scalar = WasmMessage.random();

    const sk = WasmSecretKey.random();
    const pk = sk.derive_public_key();
    const ciphertext = pk.encrypt(scalar);
    const recovered = sk.decrypt(ciphertext);

    console.log("scalar:", scalar.to_bytes());
    console.log("ciphertext:", ciphertext);
    console.log("recovered:", recovered.to_bytes());
}

main();