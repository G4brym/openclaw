---
summary: "Authenticate Gateway users via Cloudflare Access (Zero Trust) JWT"
read_when:
  - Running OpenClaw behind a Cloudflare Access tunnel
  - Setting up Cloudflare Zero Trust authentication for the Gateway
  - Fixing WebSocket 1008 unauthorized errors with Cloudflare Access
title: "Cloudflare Access"
---

# Cloudflare Access (Zero Trust)

OpenClaw supports **Cloudflare Access** as a Gateway authentication mode. When the Gateway
runs behind a Cloudflare Access application, Cloudflare authenticates users and attaches a
signed JWT (`Cf-Access-Jwt-Assertion` header) to every request. OpenClaw verifies the JWT
signature, audience, and expiry using Cloudflare's public JWKS endpoint — no shared
secrets or external dependencies required.

## How It Works

1. You create a **Cloudflare Access Application** protecting the Gateway URL
2. Cloudflare authenticates users (IdP login, one-time PIN, etc.)
3. Cloudflare adds a signed JWT in the `Cf-Access-Jwt-Assertion` header
4. OpenClaw fetches the public keys from `https://<teamDomain>.cloudflareaccess.com/cdn-cgi/access/certs`
5. OpenClaw verifies the JWT signature (RS256), audience, and expiry
6. The user email from the JWT payload is used as the authenticated identity

## Configuration

```json5
{
  gateway: {
    auth: {
      mode: "cloudflare-access",
      cloudflareAccess: {
        // Your Cloudflare Access team domain (the part before .cloudflareaccess.com)
        teamDomain: "myteam",

        // Application Audience (AUD) tag from the Access dashboard
        audience: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",

        // Optional: restrict to specific user emails
        allowUsers: ["nick@example.com", "admin@company.org"],
      },
    },
  },
}
```

### Configuration Reference

| Field                                      | Required | Description                                                                            |
| ------------------------------------------ | -------- | -------------------------------------------------------------------------------------- |
| `gateway.auth.mode`                        | Yes      | Must be `"cloudflare-access"`                                                          |
| `gateway.auth.cloudflareAccess.teamDomain` | Yes      | Your Cloudflare Access team domain (e.g. `"myteam"` for `myteam.cloudflareaccess.com`) |
| `gateway.auth.cloudflareAccess.audience`   | Yes      | Application Audience (AUD) tag from the Cloudflare Access dashboard                    |
| `gateway.auth.cloudflareAccess.allowUsers` | No       | Allowlist of user emails. Empty means allow all authenticated users.                   |

### Finding Your Configuration Values

**Team domain**: Found in the Cloudflare Zero Trust dashboard under **Settings > Custom Pages**.
It's the subdomain of `cloudflareaccess.com` (e.g., if your login URL is
`https://myteam.cloudflareaccess.com`, the team domain is `myteam`).

**Audience (AUD) tag**: Found in the Cloudflare Zero Trust dashboard under
**Access > Applications > your application > Overview**. Look for "Application Audience (AUD) Tag".

## Cloudflare Access Setup

### 1. Create a Cloudflare Tunnel

If you haven't already, create a Cloudflare Tunnel to expose your Gateway:

```bash
cloudflared tunnel create openclaw
cloudflared tunnel route dns openclaw openclaw.example.com
```

Configure the tunnel to point to your Gateway:

```yaml
# ~/.cloudflared/config.yml
tunnel: <tunnel-id>
credentials-file: /path/to/credentials.json
ingress:
  - hostname: openclaw.example.com
    service: http://localhost:18789
  - service: http_status:404
```

### 2. Create an Access Application

In the Cloudflare Zero Trust dashboard:

1. Go to **Access > Applications**
2. Click **Add an application** > **Self-hosted**
3. Set the application domain to your tunnel hostname (e.g., `openclaw.example.com`)
4. Configure your identity provider and access policies
5. Copy the **Application Audience (AUD) Tag**

### 3. Configure OpenClaw

Add the Cloudflare Access config to your OpenClaw configuration:

```json5
{
  gateway: {
    auth: {
      mode: "cloudflare-access",
      cloudflareAccess: {
        teamDomain: "myteam",
        audience: "<your-aud-tag>",
      },
    },
  },
}
```

## Security Notes

- The JWT is verified using Cloudflare's public JWKS endpoint (RS256 signatures)
- JWKS keys are cached for 5 minutes to reduce latency
- Both audience and expiry are validated before accepting the token
- Use `allowUsers` to restrict access to specific team members
- The Gateway does **not** manage the Cloudflare Tunnel or Access application — those are
  configured separately via `cloudflared` and the Cloudflare dashboard

## Troubleshooting

### "cf_access_jwt_missing"

The `Cf-Access-Jwt-Assertion` header was not present. Check:

- Is the request going through Cloudflare Access? Direct requests bypass Access and won't have the header.
- Is the Cloudflare Tunnel running and routing traffic correctly?

### "cf_access_jwt_invalid"

The JWT failed verification. Check:

- Is `teamDomain` correct? It must match your Cloudflare Access team domain exactly.
- Is `audience` correct? Copy the AUD tag from the Access dashboard.
- Is the JWT expired? Check the Cloudflare Access application session duration.
- Can the Gateway reach `https://<teamDomain>.cloudflareaccess.com`? JWKS fetching requires outbound HTTPS.

### "cf_access_user_not_allowed"

The user is authenticated but not in `allowUsers`. Either add them or remove the allowlist.

### "cf_access_config_missing"

The `cloudflareAccess` config block is missing from your Gateway auth config.

### WebSocket Connections

Cloudflare Access supports WebSocket connections. The JWT is included on the initial
WebSocket upgrade request, so authentication works the same as for HTTP requests.

## Related

- [Trusted Proxy Auth](/gateway/trusted-proxy-auth) — alternative for other identity-aware proxies
- [Tailscale](/gateway/tailscale) — alternative for tailnet-only access
- [Network Model](/gateway/network-model) — Gateway networking overview
