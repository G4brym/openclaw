/**
 * Cloudflare Access (Zero Trust) JWT verification.
 *
 * Verifies the `Cf-Access-Jwt-Assertion` header by fetching the team's
 * JWKS from `https://<teamDomain>.cloudflareaccess.com/cdn-cgi/access/certs`
 * and validating the RS256 signature, audience, and expiry.
 *
 * Uses Node.js built-in `crypto.subtle` — no external dependencies.
 */

export type CloudflareAccessIdentity = {
  email: string;
  name?: string;
};

export type CloudflareAccessVerifyConfig = {
  /** Cloudflare Access team domain (the part before `.cloudflareaccess.com`). */
  teamDomain: string;
  /** Application Audience (AUD) tag from the Cloudflare Access dashboard. */
  audience: string;
};

type JwksKey = {
  kty: string;
  kid: string;
  alg: string;
  n: string;
  e: string;
  use?: string;
};

type JwksResponse = {
  keys: JwksKey[];
};

type JwtHeader = {
  alg: string;
  kid: string;
  typ?: string;
};

type JwtPayload = {
  aud?: string | string[];
  email?: string;
  name?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  sub?: string;
  [key: string]: unknown;
};

// ── JWKS cache ──────────────────────────────────────────────────────────

type JwksCacheEntry = {
  keys: Map<string, CryptoKey>;
  expiresAt: number;
};

const jwksCache = new Map<string, JwksCacheEntry>();

const JWKS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** Visible for testing — clear the JWKS cache. */
export function clearJwksCache(): void {
  jwksCache.clear();
}

// ── Base64url helpers ───────────────────────────────────────────────────

function base64urlDecode(input: string): Uint8Array {
  // Restore padding and convert base64url → base64
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const binary = Buffer.from(padded, "base64");
  return new Uint8Array(binary);
}

// ── JWT parsing ─────────────────────────────────────────────────────────

function decodeJwtPart<T>(encoded: string): T {
  const bytes = base64urlDecode(encoded);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as T;
}

function parseJwt(
  token: string,
): { header: JwtHeader; payload: JwtPayload; signedPart: string; signature: Uint8Array } | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  try {
    const header = decodeJwtPart<JwtHeader>(parts[0]);
    const payload = decodeJwtPart<JwtPayload>(parts[1]);
    const signedPart = `${parts[0]}.${parts[1]}`;
    const signature = base64urlDecode(parts[2]);
    return { header, payload, signedPart, signature };
  } catch {
    return null;
  }
}

// ── JWKS fetching ───────────────────────────────────────────────────────

async function importRsaPublicKey(jwk: JwksKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      alg: "RS256",
      ext: true,
    },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

async function fetchJwks(
  teamDomain: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<Map<string, CryptoKey>> {
  const url = `https://${teamDomain}.cloudflareaccess.com/cdn-cgi/access/certs`;
  const response = await fetchFn(url, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${url}: ${response.status} ${response.statusText}`);
  }
  const body = (await response.json()) as JwksResponse;
  if (!body.keys || !Array.isArray(body.keys)) {
    throw new Error(`Invalid JWKS response from ${url}: missing keys array`);
  }

  const keys = new Map<string, CryptoKey>();
  for (const key of body.keys) {
    if (key.kty === "RSA" && key.kid) {
      keys.set(key.kid, await importRsaPublicKey(key));
    }
  }
  return keys;
}

async function getSigningKey(
  teamDomain: string,
  kid: string,
  fetchFn?: typeof globalThis.fetch,
): Promise<CryptoKey | null> {
  const now = Date.now();
  const cached = jwksCache.get(teamDomain);
  if (cached && cached.expiresAt > now) {
    return cached.keys.get(kid) ?? null;
  }

  try {
    const keys = await fetchJwks(teamDomain, fetchFn);
    jwksCache.set(teamDomain, { keys, expiresAt: now + JWKS_CACHE_TTL_MS });
    return keys.get(kid) ?? null;
  } catch {
    // If fetch fails but we have stale cache, use it
    if (cached) {
      return cached.keys.get(kid) ?? null;
    }
    return null;
  }
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Verify a Cloudflare Access JWT token.
 *
 * @returns The identity if the token is valid, or `null` if verification fails.
 */
export async function verifyCloudflareAccessJwt(
  token: string,
  config: CloudflareAccessVerifyConfig,
  options?: {
    /** Override fetch for testing. */
    fetchFn?: typeof globalThis.fetch;
    /** Override current time (epoch ms) for testing. */
    nowMs?: number;
  },
): Promise<CloudflareAccessIdentity | null> {
  const parsed = parseJwt(token);
  if (!parsed) {
    return null;
  }

  const { header, payload, signedPart, signature } = parsed;

  // Only RS256 is supported by Cloudflare Access
  if (header.alg !== "RS256") {
    return null;
  }

  // Verify audience
  const audiences = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
  if (!audiences.includes(config.audience)) {
    return null;
  }

  // Verify expiry
  const nowSec = Math.floor((options?.nowMs ?? Date.now()) / 1000);
  if (typeof payload.exp === "number" && payload.exp < nowSec) {
    return null;
  }

  // Get the signing key
  const key = await getSigningKey(config.teamDomain, header.kid, options?.fetchFn);
  if (!key) {
    return null;
  }

  // Verify signature
  const data = new TextEncoder().encode(signedPart);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  if (!valid) {
    return null;
  }

  // Extract identity
  if (!payload.email || typeof payload.email !== "string") {
    return null;
  }

  return {
    email: payload.email,
    name: typeof payload.name === "string" && payload.name.trim() ? payload.name.trim() : undefined,
  };
}
