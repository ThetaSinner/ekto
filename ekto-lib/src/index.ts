import _sodium, {KeyPair} from "libsodium-wrappers-sumo";
import {
    CallZomeRequest,
    CallZomeRequestSigned,
    CallZomeRequestUnsigned, getNonceExpiration, hashZomeCall,
    randomNonce,
} from "@holochain/client";
import {encode} from "@msgpack/msgpack";

/**
 * Converts a password and a salt and returns a keypair.
 *
 * The salt should be cached and re-used. If it is lost, then the same password will result
 * in a new keypair that must be granted access to Holochain.
 *
 * @param password The password to generate the keypair
 * @param salt The salt provided by the server
 *
 * @returns {Promise<KeyPair>} The keypair generated from the password and salt
 */
export async function generateKey(password: string, salt: Uint8Array): Promise<KeyPair> {
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
        password,
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

/**
 * Creates a function that can be used to sign {@link CallZomeRequest}s.
 *
 * The {@link KeyPair} should be generated using {@link generateKey}.
 *
 * @param keyPair The keypair to use for signing
 *
 * @returns {Promise<(request: CallZomeRequest) => Promise<CallZomeRequestSigned>>} Function to sign {@link CallZomeRequest}s
 */
export async function zomeCallSignerFactory(keyPair: KeyPair): Promise<(CallZomeRequest) => Promise<CallZomeRequestSigned>> {
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

/**
 * Injects a form to collect the password for {@link generateKey}.
 *
 * The form will be inserted at the beginning of the body. It takes up the whole view height and width.
 * It appears a bit like an overlay but isn't. The user will be able to scroll down and see the app UI.
 *
 * This integration is not ideal and any zome calls made before the user submits and approves the password will fail.
 * This can be used to integrate with apps that don't have an integration with Ekto. However, it would be better to
 * have the application be aware of Ekto and prompt the user for the password when needed.
 *
 * The form will have a password input and a submit button. The submit button will call the {@link submitCallback} function.
 * The {@link submitCallback} function must prevent form submission so that the page does not reload. Otherwise, the form
 * will just end up being shown again.
 *
 * @param submitCallback Callback function to run when the form is submitted.
 *
 * @returns {void}
 */
export function injectPasswordForm(submitCallback: (e: Event) => boolean) {
    const container = document.createElement("div");
    container.setAttribute("style", "height: 100vh; width: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center;");
    container.setAttribute("id", "ekto-auth-container");
    document.body.insertBefore(container, document.body.firstChild);

    const form = document.createElement("form");
    form.setAttribute("style", "width: 25%;");
    form.onsubmit = submitCallback;
    container.appendChild(form);

    const label = document.createElement("label");
    label.innerText = "Ekto password:";
    label.setAttribute("for", "ekto-password");
    form.appendChild(label);

    const formSection = document.createElement("div");
    formSection.setAttribute("style", "display: flex; flex-direction: row;");
    form.appendChild(formSection);

    const input = document.createElement("input");
    input.setAttribute("type", "password");
    input.setAttribute("id", "ekto-password");
    input.setAttribute("style", "height: 3.5em; flex-grow: 3; background-color: aliceblue; margin-right: 5px; padding: 5px; border-radius: 5px;");
    formSection.appendChild(input);

    const button = document.createElement("button");
    button.innerText = "Submit";
    button.setAttribute("style", "background: azure; padding: 1em; border-radius: 5px;");
    button.setAttribute("type", "submit");
    formSection.appendChild(button);
}

/**
 * Removes the password form injected by {@link injectPassphraseForm}.
 *
 * @returns {void}
 */
export function removePasswordForm() {
    document.getElementById("ekto-auth-container").remove();
}

/**
 * Convenience function to integration with the @holochain/client library for zome call signing.
 *
 * This function will generate a keypair using the password and salt provided. It will then create a zome call signer
 * with the keypair and {@link zomeCallSignerFactory}. A reference to the signer will be stored in the window object
 * where the @holochain/client library will look for it.
 *
 * @param password The password to generate the keypair
 * @param salt The salt provided by the server
 *
 * @returns {Promise<void>}
 */
export async function configureZomeCallSigner(password: string, salt: Uint8Array): Promise<void> {
    const keyPair = await generateKey(password, Uint8Array.from(salt));

    const signer = await zomeCallSignerFactory(keyPair);
    window["__HC_ZOME_CALL_SIGNER__"] = {
        signZomeCall: signer,
    };
}
