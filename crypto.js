/**
 * crypto.js — client-side end-to-end encryption
 * ------------------------------------------------------------------
 * Uses ONLY the browser's built-in Web Crypto API (window.crypto.subtle).
 * No custom cryptography, no third-party crypto libraries.
 *
 * Primitives:
 *   - Key exchange:   ECDH on curve P-256
 *   - Message cipher: AES-GCM, 256-bit key, random 96-bit IV per message
 *
 * Model:
 *   - Each account gets one ECDH keypair, generated on the device at
 *     registration.
 *   - The PUBLIC key is uploaded to Supabase (profiles.public_key) so
 *     other users can encrypt messages to this account. It is not secret.
 *   - The PRIVATE key NEVER leaves this device. It is kept only in the
 *     browser's IndexedDB (see keyStore below) and is never sent to
 *     Supabase in any form.
 *   - To send Alice -> Bob: Alice derives a shared AES key from her own
 *     private key + Bob's public key (ECDH), then encrypts with AES-GCM.
 *   - To read it: Bob derives the SAME shared AES key from his own
 *     private key + Alice's public key, then decrypts.
 *   - ECDH is symmetric this way: (Alice priv, Bob pub) and
 *     (Bob priv, Alice pub) produce the identical shared secret.
 *
 * HONEST LIMITATION (see README.md "Encryption model & its real limits"
 * for the full picture — do not remove this comment, it documents a
 * real constraint of the architecture, per spec section 15):
 *   Because the private key lives only in this browser's IndexedDB,
 *   logging in on a new device or clearing site data means the OLD
 *   private key is gone. Old messages encrypted to the old public key
 *   become permanently undecryptable on that new device (they still
 *   exist as ciphertext on the server, but nothing can open them).
 *   This app does NOT implement multi-device key sync or key backup —
 *   doing that safely is a substantial protocol on its own (this is
 *   exactly what Signal's "sealed sender" + safety-number + device-
 *   linking system solves) and is out of scope for this minimal stack.
 *   This app also does not protect against a compromised endpoint
 *   (e.g. malware on your phone, or someone with your unlocked phone)
 *   or against a screenshot taken by the other participant. It is not
 *   "untraceable" or "impossible to track": Supabase still knows WHO
 *   messaged WHOM and WHEN (sender_id, receiver_id, created_at are not
 *   encrypted, only the message text is).
 */

const EC_CURVE = "P-256";
const AES_LENGTH = 256;
const DB_NAME = "messenger-keys";
const DB_STORE = "keys";
const PRIVATE_KEY_ENTRY = "device-private-key";

// ---------------------------------------------------------------------
// IndexedDB helpers — this is the ONLY place the private key is stored.
// ---------------------------------------------------------------------

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(DB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readonly");
    const req = tx.objectStore(DB_STORE).get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key, value) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbClear() {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------
// Base64 <-> ArrayBuffer helpers
// ---------------------------------------------------------------------

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ---------------------------------------------------------------------
// Keypair generation / storage
// ---------------------------------------------------------------------

/**
 * Generates a fresh ECDH keypair for this device, stores the private
 * key locally (IndexedDB, non-extractable-in-practice usage pattern:
 * we mark it extractable=true only because we need to persist it
 * ourselves across page reloads via structured clone; it is still never
 * transmitted anywhere), and returns the exportable public key as a
 * JSON string ready to save in profiles.public_key.
 */
async function generateAndStoreKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: EC_CURVE },
    true,
    ["deriveKey", "deriveBits"]
  );

  await idbSet(PRIVATE_KEY_ENTRY, keyPair.privateKey);

  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return JSON.stringify(publicJwk);
}

/** Returns the device's stored private CryptoKey, or null if none exists. */
async function getStoredPrivateKey() {
  return idbGet(PRIVATE_KEY_ENTRY);
}

/** True if this device has a private key ready to use. */
async function hasDeviceKey() {
  const key = await getStoredPrivateKey();
  return key !== null;
}

/** Wipes the local private key (used on logout is NOT necessary, but on
 * account deletion we clear it so a reused browser doesn't hold onto a
 * stale key). */
async function clearDeviceKey() {
  await idbClear();
}

async function importPublicKeyFromJson(jsonStr) {
  const jwk = JSON.parse(jsonStr);
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: EC_CURVE },
    true,
    []
  );
}

// ---------------------------------------------------------------------
// Shared-secret derivation + AES-GCM encrypt/decrypt
// ---------------------------------------------------------------------

async function deriveSharedAesKey(myPrivateKey, theirPublicKeyJson) {
  const theirPublicKey = await importPublicKeyFromJson(theirPublicKeyJson);
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: theirPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: AES_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts `plaintext` so that the holder of `theirPublicKeyJson`'s
 * matching private key can decrypt it. Returns a JSON string:
 *   { "iv": "<base64>", "ciphertext": "<base64>" }
 * ready to store directly in messages.message_content.
 */
async function encryptMessage(plaintext, theirPublicKeyJson) {
  const myPrivateKey = await getStoredPrivateKey();
  if (!myPrivateKey) throw new Error("No local encryption key on this device.");

  const aesKey = await deriveSharedAesKey(myPrivateKey, theirPublicKeyJson);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoded
  );

  return JSON.stringify({
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(ciphertextBuf),
  });
}

/**
 * Decrypts a stored message_content JSON string. `theirPublicKeyJson`
 * must be the OTHER participant's public key (the sender, if I'm
 * reading an incoming message; the receiver, if I'm re-reading my own
 * sent message).
 * Returns the plaintext string, or throws if it cannot be decrypted
 * (e.g. this device never had the matching private key).
 */
async function decryptMessage(storedJson, theirPublicKeyJson) {
  const myPrivateKey = await getStoredPrivateKey();
  if (!myPrivateKey) throw new Error("No local encryption key on this device.");

  const { iv, ciphertext } = JSON.parse(storedJson);
  const aesKey = await deriveSharedAesKey(myPrivateKey, theirPublicKeyJson);

  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuf(iv) },
    aesKey,
    base64ToBuf(ciphertext)
  );

  return new TextDecoder().decode(plainBuf);
}

window.MessengerCrypto = {
  generateAndStoreKeyPair,
  hasDeviceKey,
  clearDeviceKey,
  encryptMessage,
  decryptMessage,
};
