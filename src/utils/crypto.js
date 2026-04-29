// Utility functions for ArrayBuffer <-> Base64 conversion
export function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// 1. RSA Key Generation (2048-bit)
export async function generateRSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true, // extractable
    ["encrypt", "decrypt"]
  );

  const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);

  return {
    privateKey: keyPair.privateKey,
    publicKeyBase64,
  };
}

// Import Base64 Public Key
export async function importRSAPublicKey(base64Key) {
  const buffer = base64ToArrayBuffer(base64Key);
  return await window.crypto.subtle.importKey(
    "spki",
    buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

// 2. AES Key Generation (AES-GCM 256-bit)
export async function generateAESKey() {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// Export AES Key to Base64 (so we can encrypt it via RSA)
export async function exportAESKey(aesKey) {
  const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);
  return arrayBufferToBase64(rawKey);
}

// Import AES Key from Base64
export async function importAESKey(base64Key) {
  const buffer = base64ToArrayBuffer(base64Key);
  return await window.crypto.subtle.importKey(
    "raw",
    buffer,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

// 3. Encrypt AES Key using RSA Public Key
export async function rsaEncrypt(publicKey, dataBase64) {
  const dataBuffer = base64ToArrayBuffer(dataBase64);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    dataBuffer
  );
  return arrayBufferToBase64(encrypted);
}

// Decrypt AES Key using RSA Private Key
export async function rsaDecrypt(privateKey, encryptedBase64) {
  const encryptedBuffer = base64ToArrayBuffer(encryptedBase64);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBuffer
  );
  return arrayBufferToBase64(decrypted);
}

// 4. Encrypt Message using AES-GCM
export async function aesEncryptMessage(aesKey, messageText) {
  const encoder = new TextEncoder();
  const data = encoder.encode(messageText);

  // Secure Random IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    data
  );

  return {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(encryptedBuffer),
  };
}

// 5. Decrypt Message using AES-GCM
export async function aesDecryptMessage(aesKey, ivBase64, ciphertextBase64) {
  const iv = base64ToArrayBuffer(ivBase64);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);

  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      aesKey,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (err) {
    console.error("Decryption failed. Integrity check failed or wrong key.");
    return "[DECRYPTION FAILED - INTEGRITY COMPROMISED]";
  }
}

// Password Hashing (SHA-256)
export async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return arrayBufferToBase64(hashBuffer);
}
