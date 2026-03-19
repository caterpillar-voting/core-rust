import init, {
    WasmSecretKey,
    WasmMessage,
} from "./pkg/caterpillar_voting_core_wasm.js";

async function main() {
    await init();
    
    const payload = new Uint8Array(32);
    payload.fill(1);
    const scalar = WasmMessage.from_bytes(payload);

    const sk = WasmSecretKey.random();
    const pk = sk.derive_public_key();
    const ciphertext = pk.encrypt(scalar);
    const recovered = sk.decrypt(ciphertext);

    console.log("scalar:", scalar.to_bytes());
    console.log("ciphertext:", ciphertext);
    console.log("recovered:", recovered.to_bytes());
}

main();