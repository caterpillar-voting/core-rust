import init, { WasmEncryption,WasmEncodedMessage} from "./pkg/caterpillar_voting_core_wasm.js";

async function main() {
    await init();

    const encryption = WasmEncryption.new();
    const keyPair = encryption.key_gen();

    const message = WasmEncodedMessage.from()
    const ciphertext = encryption.encrypt(keyPair.public, message);
    const recovered = encryption.decrypt(keyPair.private, ciphertext);

    console.log("message:", message.to_bytes());
    console.log("ciphertext:", ciphertext);
    console.log("recovered:", recovered.to_bytes());
}

main();