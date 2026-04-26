import { SignJWT, jwtVerify, type JWTPayload } from "jose";

// Base64 helpers
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function importAesKey(keyB64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(keyB64);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export interface EncryptedPayload {
  iv: string;
  ct: string;
  aad: string;
}

export async function encryptPayload(plaintext: string, aad: string, keyB64: string): Promise<EncryptedPayload> {
  const key = await importAesKey(keyB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aadBytes = new TextEncoder().encode(aad);
  const ptBytes = new TextEncoder().encode(plaintext);
  const ctBytes = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 },
    key,
    ptBytes
  );
  return {
    iv: bytesToBase64Url(iv),
    ct: bytesToBase64Url(new Uint8Array(ctBytes)),
    aad: bytesToBase64Url(aadBytes),
  };
}

export async function decryptPayload(payload: EncryptedPayload, keyB64: string): Promise<string> {
  const key = await importAesKey(keyB64);
  const iv = base64ToBytes(payload.iv);
  const ct = base64ToBytes(payload.ct);
  const aad = base64ToBytes(payload.aad);
  const ptBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    ct
  );
  return new TextDecoder().decode(ptBytes);
}

async function importHmacKey(keyB64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(keyB64);
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signCsrf(data: string, keyB64: string): Promise<string> {
  const key = await importHmacKey(keyB64);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

export async function verifyCsrf(data: string, sig: string, keyB64: string): Promise<boolean> {
  const key = await importHmacKey(keyB64);
  const sigBytes = base64ToBytes(sig);
  return crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
}

async function importHs256Key(keyB64: string): Promise<Uint8Array> {
  return base64ToBytes(keyB64);
}

export async function signJwt(payload: JWTPayload, keyB64: string, expiresInSeconds: number): Promise<string> {
  const secret = await importHs256Key(keyB64);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + expiresInSeconds)
    .sign(secret);
}

export interface VerifiedJwt {
  payload: JWTPayload & Record<string, unknown>;
}

export async function verifyJwt(
  token: string,
  keyB64: string,
  options?: { issuer?: string; audience?: string }
): Promise<VerifiedJwt> {
  const secret = await importHs256Key(keyB64);
  const { payload } = await jwtVerify(token, secret, {
    issuer: options?.issuer,
    audience: options?.audience,
  });
  return { payload: payload as JWTPayload & Record<string, unknown> };
}
