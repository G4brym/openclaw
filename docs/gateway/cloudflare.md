---
summary: "Expose the Gateway via Cloudflare Tunnel with Cloudflare Access authentication"
read_when:
  - setting up Cloudflare Tunnel for remote access
  - configuring Cloudflare Access authentication
  - running openclaw behind cloudflared
title: "Cloudflare Tunnel & Access"
---

# Cloudflare Tunnel & Access

OpenClaw can integrate with Cloudflare Tunnel and Cloudflare Access to expose the
Gateway securely over the internet with identity-aware authentication.

## Modes

- `managed`: OpenClaw spawns and manages a `cloudflared tunnel run` process using a
  tunnel token. Also verifies Cloudflare Access JWTs for authentication.
- `access-only`: You run `cloudflared` (or any Cloudflare routing) externally.
  OpenClaw only verifies incoming Cloudflare Access JWT headers.
- `off`: Default (no Cloudflare integration).

## Prerequisites

- A Cloudflare account with Zero Trust enabled
- A Cloudflare Tunnel configured in the Zero Trust dashboard
- The `cloudflared` binary installed (managed mode)
- A Cloudflare Access application configured for JWT verification

## Setup: Managed mode

1. Create a tunnel in the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/)
2. Copy the tunnel token
3. Create a Cloudflare Access application for your tunnel hostname
4. Note your team domain (e.g. `myteam` from `myteam.cloudflareaccess.com`)
5. Configure OpenClaw:

```json5
{
  gateway: {
    bind: "loopback",
    cloudflare: {
      mode: "managed",
      tunnelToken: "eyJ...", // or use OPENCLAW_CLOUDFLARE_TUNNEL_TOKEN env var
      teamDomain: "myteam",
      audience: "abc123...", // optional Application Audience tag
    },
  },
}
```

OpenClaw will spawn `cloudflared tunnel run`, which connects to the Cloudflare edge
and routes traffic to your local Gateway port.

## Setup: Access-only mode

Use this when you manage `cloudflared` yourself (e.g. via systemd, Docker, or
Cloudflare's managed connector).

1. Configure your external `cloudflared` to point to the Gateway port
2. Create a Cloudflare Access application for the tunnel hostname
3. Configure OpenClaw:

```json5
{
  gateway: {
    bind: "loopback", // or "lan" if cloudflared runs on another host
    cloudflare: {
      mode: "access-only",
      teamDomain: "myteam",
      audience: "abc123...", // optional
    },
  },
}
```

## Authentication

When cloudflare mode is active, OpenClaw verifies the `Cf-Access-Jwt-Assertion`
header on incoming requests. The JWT is validated against the JWKS endpoint at
`https://<teamDomain>.cloudflareaccess.com/cdn-cgi/access/certs`.

Verification checks:

- JWT signature (RS256/ES256 via JWKS)
- Expiry (`exp` claim)
- Issuer (`iss` must match `https://<teamDomain>.cloudflareaccess.com`)
- Audience (`aud` must match configured audience, if set)

On success, the user's email from the JWT `email` claim is used as the authenticated
identity (auth method: `cloudflare-access`).

### Auth interaction

By default, `allowCloudflareAccess` is `true` when cloudflare mode is `managed` or
`access-only` (unless auth mode is `trusted-proxy`). Cloudflare Access JWT
verification runs after Tailscale identity checks and before token/password auth.

To disable Cloudflare Access identity and require explicit credentials:

```json5
{
  gateway: {
    cloudflare: { mode: "managed" /* ... */ },
    auth: { allowCloudflareAccess: false },
  },
}
```

## CLI examples

```bash
# Managed mode
openclaw gateway --cloudflare managed \
  --cloudflare-tunnel-token "eyJ..." \
  --cloudflare-team-domain myteam

# Access-only mode
openclaw gateway --cloudflare access-only \
  --cloudflare-team-domain myteam \
  --cloudflare-audience "abc123..."
```

## Environment variables

| Variable                           | Description                                               |
| ---------------------------------- | --------------------------------------------------------- |
| `OPENCLAW_CLOUDFLARE_TUNNEL_TOKEN` | Tunnel token for managed mode (alternative to config/CLI) |

## Configuration reference

| Field                                | Type                                      | Required              | Description                              |
| ------------------------------------ | ----------------------------------------- | --------------------- | ---------------------------------------- |
| `gateway.cloudflare.mode`            | `"off"` \| `"managed"` \| `"access-only"` | No                    | Cloudflare mode (default: `off`)         |
| `gateway.cloudflare.tunnelToken`     | string                                    | Managed only          | Tunnel token from Zero Trust dashboard   |
| `gateway.cloudflare.teamDomain`      | string                                    | Managed + Access-only | Team domain for JWKS endpoint            |
| `gateway.cloudflare.audience`        | string                                    | No                    | Application Audience (AUD) tag           |
| `gateway.auth.allowCloudflareAccess` | boolean                                   | No                    | Allow CF Access JWT auth (default: auto) |

## Validation rules

| Mode          | Requires                     | Bind     | Notes                            |
| ------------- | ---------------------------- | -------- | -------------------------------- |
| `off`         | nothing                      | any      | Default                          |
| `managed`     | `tunnelToken` + `teamDomain` | loopback | cloudflared proxies to localhost |
| `access-only` | `teamDomain`                 | any      | External cloudflared expected    |

## Learn more

- Cloudflare Tunnel: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
- Cloudflare Access: https://developers.cloudflare.com/cloudflare-one/policies/access/
- Zero Trust dashboard: https://one.dash.cloudflare.com/
