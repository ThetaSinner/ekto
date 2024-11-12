import _sodium from "libsodium-wrappers-sumo";

export async function generateKey (pass: string, salt: Uint8Array) {
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
