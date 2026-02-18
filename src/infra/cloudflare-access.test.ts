import { describe, expect, it, beforeEach } from "vitest";
import { verifyCloudflareAccessJwt, clearJwksCache } from "./cloudflare-access.js";

// ── Test helpers: generate RS256 key pair and sign JWTs ──────────────

async function generateRsaKeyPair(): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

function jsonBase64url(obj: Record<string, unknown>): string {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

async function signJwt(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  kid: string,
): Promise<string> {
  const header = { alg: "RS256", kid, typ: "JWT" };
  const headerEncoded = jsonBase64url(header);
  const payloadEncoded = jsonBase64url(payload);
  const signingInput = `${headerEncoded}.${payloadEncoded}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

async function exportJwk(key: CryptoKey, kid: string): Promise<Record<string, unknown>> {
  const exported = await crypto.subtle.exportKey("jwk", key);
  return { ...exported, kid, use: "sig" };
}

function createMockFetch(jwks: { keys: Record<string, unknown>[] }): typeof globalThis.fetch {
  return (async () => ({
    ok: true,
    json: async () => jwks,
  })) as unknown as typeof globalThis.fetch;
}

// ── Tests ───────────────────────────────────────────────────────────────

const TEST_TEAM_DOMAIN = "myteam";
const TEST_AUDIENCE = "test-aud-123456";
const TEST_KID = "test-key-1";
const CONFIG = { teamDomain: TEST_TEAM_DOMAIN, audience: TEST_AUDIENCE };

describe("cloudflare-access JWT verification", () => {
  let publicKey: CryptoKey;
  let privateKey: CryptoKey;
  let mockFetch: typeof globalThis.fetch;

  beforeEach(async () => {
    clearJwksCache();
    const pair = await generateRsaKeyPair();
    publicKey = pair.publicKey;
    privateKey = pair.privateKey;
    const jwk = await exportJwk(publicKey, TEST_KID);
    mockFetch = createMockFetch({ keys: [jwk] });
  });

  it("verifies a valid JWT and returns identity", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      {
        aud: TEST_AUDIENCE,
        email: "nick@example.com",
        name: "Nick",
        exp: now + 3600,
        iat: now,
        iss: `https://${TEST_TEAM_DOMAIN}.cloudflareaccess.com`,
        sub: "user-id-123",
      },
      privateKey,
      TEST_KID,
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toEqual({ email: "nick@example.com", name: "Nick" });
  });

  it("returns identity without name when name is absent", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: TEST_AUDIENCE, email: "nick@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toEqual({ email: "nick@example.com", name: undefined });
  });

  it("rejects an expired JWT", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: TEST_AUDIENCE, email: "nick@example.com", exp: now - 100 },
      privateKey,
      TEST_KID,
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toBeNull();
  });

  it("rejects a JWT with wrong audience", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: "wrong-audience", email: "nick@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toBeNull();
  });

  it("rejects a JWT with invalid signature", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: TEST_AUDIENCE, email: "nick@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );

    // Tamper with the signature
    const parts = token.split(".");
    const tampered = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -4)}AAAA`;

    const identity = await verifyCloudflareAccessJwt(tampered, CONFIG, { fetchFn: mockFetch });
    expect(identity).toBeNull();
  });

  it("rejects a JWT with unknown kid", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: TEST_AUDIENCE, email: "nick@example.com", exp: now + 3600 },
      privateKey,
      "unknown-kid",
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toBeNull();
  });

  it("rejects a JWT missing email", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt({ aud: TEST_AUDIENCE, exp: now + 3600 }, privateKey, TEST_KID);

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toBeNull();
  });

  it("rejects malformed tokens", async () => {
    expect(await verifyCloudflareAccessJwt("not-a-jwt", CONFIG, { fetchFn: mockFetch })).toBeNull();
    expect(await verifyCloudflareAccessJwt("", CONFIG, { fetchFn: mockFetch })).toBeNull();
    expect(await verifyCloudflareAccessJwt("a.b", CONFIG, { fetchFn: mockFetch })).toBeNull();
  });

  it("rejects a JWT with non-RS256 algorithm", async () => {
    // Manually craft a JWT header with HS256
    const header = jsonBase64url({ alg: "HS256", kid: TEST_KID, typ: "JWT" });
    const payload = jsonBase64url({
      aud: TEST_AUDIENCE,
      email: "nick@example.com",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const fakeToken = `${header}.${payload}.fakesig`;

    const identity = await verifyCloudflareAccessJwt(fakeToken, CONFIG, { fetchFn: mockFetch });
    expect(identity).toBeNull();
  });

  it("supports audience as array", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: ["other-aud", TEST_AUDIENCE], email: "nick@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: mockFetch });
    expect(identity).toEqual({ email: "nick@example.com", name: undefined });
  });

  it("uses nowMs override for expiry check", async () => {
    const token = await signJwt(
      { aud: TEST_AUDIENCE, email: "nick@example.com", exp: 1000 },
      privateKey,
      TEST_KID,
    );

    // Token exp=1000, so if now is 500 (sec) it should be valid
    const identity = await verifyCloudflareAccessJwt(token, CONFIG, {
      fetchFn: mockFetch,
      nowMs: 500 * 1000,
    });
    expect(identity).toEqual({ email: "nick@example.com", name: undefined });

    // But if now is 1001 (sec) it should be expired
    const expired = await verifyCloudflareAccessJwt(token, CONFIG, {
      fetchFn: mockFetch,
      nowMs: 1001 * 1000,
    });
    expect(expired).toBeNull();
  });

  it("caches JWKS and reuses on subsequent calls", async () => {
    let fetchCount = 0;
    const countingFetch: typeof globalThis.fetch = (async (
      ...args: Parameters<typeof globalThis.fetch>
    ) => {
      fetchCount++;
      return mockFetch(...args);
    }) as typeof globalThis.fetch;

    const now = Math.floor(Date.now() / 1000);
    const token1 = await signJwt(
      { aud: TEST_AUDIENCE, email: "alice@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );
    const token2 = await signJwt(
      { aud: TEST_AUDIENCE, email: "bob@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );

    await verifyCloudflareAccessJwt(token1, CONFIG, { fetchFn: countingFetch });
    await verifyCloudflareAccessJwt(token2, CONFIG, { fetchFn: countingFetch });

    expect(fetchCount).toBe(1);
  });

  it("returns null when JWKS fetch fails", async () => {
    const failingFetch = (async () => ({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    })) as unknown as typeof globalThis.fetch;

    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { aud: TEST_AUDIENCE, email: "nick@example.com", exp: now + 3600 },
      privateKey,
      TEST_KID,
    );

    const identity = await verifyCloudflareAccessJwt(token, CONFIG, { fetchFn: failingFetch });
    expect(identity).toBeNull();
  });
});
