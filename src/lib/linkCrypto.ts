import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

// Link URLs are encrypted at rest with AES-256-GCM using one app-wide key.
// Stored format: "enc:v1:" + base64(iv[12] | authTag[16] | ciphertext).
// The version in the prefix leaves room for key rotation later.
const PREFIX = "enc:v1:";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

let cachedKey: Buffer | null = null;

// Loaded lazily so a missing env var fails the request that needs it, not the build.
function getKey(): Buffer {
    if (cachedKey) return cachedKey;
    const raw = process.env.LINK_ENC_KEY;
    if (!raw) throw new Error("LINK_ENC_KEY is not set");
    const key = Buffer.from(raw, "base64");
    if (key.length !== 32) throw new Error("LINK_ENC_KEY must be 32 bytes, base64-encoded");
    cachedKey = key;
    return key;
}

export function isEncrypted(value: string): boolean {
    return value.startsWith(PREFIX);
}

export function encryptLink(plain: string): string {
    const iv = randomBytes(IV_LENGTH); // fresh IV per value; never reuse with the same key
    const cipher = createCipheriv("aes-256-gcm", getKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    return PREFIX + Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64");
}

/** Decrypts an encrypted link. Plaintext values (not yet migrated) are returned as-is. */
export function decryptLink(value: string): string {
    if (!isEncrypted(value)) return value;
    const buf = Buffer.from(value.slice(PREFIX.length), "base64");
    const iv = buf.subarray(0, IV_LENGTH);
    const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const ciphertext = buf.subarray(IV_LENGTH + TAG_LENGTH);
    const decipher = createDecipheriv("aes-256-gcm", getKey(), iv);
    decipher.setAuthTag(tag); // GCM: throws on final() if the value was tampered with or the key is wrong
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
