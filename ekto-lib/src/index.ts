import _sodium, {KeyPair} from "libsodium-wrappers-sumo";
import {
    CallZomeRequest,
    CallZomeRequestSigned,
    CallZomeRequestUnsigned, getNonceExpiration, hashZomeCall,
    randomNonce,
    signZomeCall
} from "@holochain/client";
import {encode} from "@msgpack/msgpack";

export async function generateKey(pass: string, salt: Uint8Array) {
    await _sodium.ready;
    const sodium = _sodium;

    let newKeypair = false;
    let useSalt = salt;

    // Not secure, find a better way to retain this salt. Maybe IndexedDB?
    if (typeof localStorage !== "undefined") {
        let loadedSalt = localStorage.getItem("ekto-salt");
        if (loadedSalt !== null) {
            useSalt = new Uint8Array(JSON.parse(loadedSalt));
            if (useSalt.length != 16) {
                newKeypair = true;
                localStorage.setItem("ekto-salt", JSON.stringify(Array.from(salt)));
            }
        } else {
            newKeypair = true;
            localStorage.setItem("ekto-salt", JSON.stringify(Array.from(salt)));
        }
    }

    const out = sodium.crypto_pwhash(
        32,
        pass,
        useSalt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT,
    );

    const keypair = sodium.crypto_sign_seed_keypair(out);

    if (newKeypair) {
        const response = await fetch("/ekto-register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                publicKey: Array.from(keypair.publicKey),
            }),
        });

        if (!response.ok) {
            console.error("Failed to register public key", response);
        }
    }

    return keypair;
}

export async function zomeCallSignerFactory(keyPair: KeyPair) {
    const provenance = new Uint8Array([132, 32, 36].concat(...keyPair.publicKey).concat([0, 0, 0, 0]));

    await _sodium.ready;
    const sodium = _sodium;

    return async function zomeCallSigner(request: CallZomeRequest): Promise<CallZomeRequestSigned> {
        const unsignedZomeCallPayload: CallZomeRequestUnsigned = {
            cap_secret: Uint8Array.from([...keyPair.publicKey, ...keyPair.publicKey]),
            cell_id: request.cell_id,
            zome_name: request.zome_name,
            fn_name: request.fn_name,
            provenance: provenance,
            payload: encode(request.payload),
            nonce: await randomNonce(),
            expires_at: getNonceExpiration(),
        };
        const hashedZomeCall = await hashZomeCall(unsignedZomeCallPayload);
        const signature = sodium
            .crypto_sign(hashedZomeCall, keyPair.privateKey)
            .subarray(0, sodium.crypto_sign_BYTES);

        return {
            ...unsignedZomeCallPayload,
            signature,
        } as CallZomeRequestSigned;
    };
}
