---
description: How storage-service verifies identity-service JWTs, and which claims it trusts for staff, owners, and company scope.
---

# JWT and claim trust

storage-service checks Bearer JWTs from identity-service and reads a few claims for authorization. It does not store users, and it does not call identity-service again on each API request.

Send the token as `Authorization: Bearer your_access_token_here`.

## What gets verified

Tokens must include `exp`. The signature is checked as RS256 against a JSON Web Key Set (JWKS). Pin that document in production with `IDENTITY_JWKS_FILE` or `IDENTITY_JWKS`. Local development can fetch `IDENTITY_JWKS_URL`, which defaults to `{IDENTITY_SERVICE_URL}/.well-known/jwks.json`.

Copy the public JWKS from a machine that can reach identity-service. Do not fetch `https://id.shellui.com/.well-known/jwks.json` from a container on the same host. That request hairpins and times out.

```bash
curl -sS https://id.shellui.com/.well-known/jwks.json
```

Set one of these and restart:

```bash
IDENTITY_JWKS_FILE=/app/data/jwks.json
```

Or set `IDENTITY_JWKS` to the same JSON object, including a non-empty `keys` array. An empty `keys` array refuses to start. When either variable is set, verification uses that document and does not call identity-service at runtime. After identity-service rotates signing keys, update the JSON and restart storage-service.

Startup with `DEBUG=false` fails unless both of these are set:

- `IDENTITY_ISSUER`: the JWT `iss` claim must match
- `IDENTITY_AUDIENCE`: the JWT `aud` claim must match

A missing pin does not, by itself, refuse to start. Set the pin anyway so production does not depend on a runtime fetch.

`JWT_HS256_FALLBACK_SECRET` verifies HS256 tokens from a local identity-service debug setup. Set it to that service's `SECRET_KEY`. storage-service refuses to start with the secret set while `DEBUG=false`, unless `ALLOW_JWT_HS256_FALLBACK=true`.

Issuer and audience checks run only when the matching variable is set. Production always sets both.

`GET /storage/v1/health` without a token returns `status` and `version` only. With a valid Bearer token, the same response adds `storage_backend`, `identity_jwks_source` (`env`, `file`, or `url`), and `identity_jwks_url`.

## Claims storage-service trusts

These claims are taken from the verified payload. storage-service does not ask identity-service whether they are still true on the next request:

| Claim | Used for |
| --- | --- |
| `user_metadata.is_staff` | Quota changes for any company, global stats, global metrics, Shellui Actions for any `company_id` |
| `user_metadata.is_company_owner` | Quota changes for the token's company, company metrics, Shellui Actions for that company |
| `pat_agm` | Global Prometheus metrics for a personal access token (PAT) issued by staff |
| `company_id` | Which company's bucket, objects, quota, and events this caller may touch |
| `user_id` or `sub` | Numeric identity user id stored as the object owner and on the event log |
| `email` | Actor email on events, when the token carries one |

A forged payload cannot pass unless it is signed by a key in the JWKS. Privileged routes rely on that signature check and on token expiry.

The optional `apikey` header is allowed by CORS and ignored for authorization.

## Company scope

Object and bucket routes compare `company_id` on the token with the row. You only see your company's files.

Staff tokens can `PUT` quotas for a `company_id` in the path and can read `GET /storage/v1/stats` with no company filter. Other callers see stats for their company only. `days` on that route is from 1 to 90 and defaults to 14.

`GET /storage/v1/metrics` uses the company on the token and requires staff or a company owner. A `company_id` query parameter is 400. `GET /storage/v1/metrics/all` requires staff or `pat_agm`.

Shellui Actions routes under `/api/v1/actions/` let staff pass any `company_id` query parameter. Company owners may omit it and then the token company is used. Another company returns 403. A caller who is neither staff nor a company owner receives 403.

## When verification fails

The API returns 401 and does not echo the token. Process logs on `apps.authapi.authentication` include `alg`, `kid`, `iss`, `aud`, `jwks_source`, and `jwks_kids`. The same `request_id` is the `X-Request-ID` response header and the `request_id` field on the error JSON.

`HS256` with no fallback means identity-service is in debug mode: set `JWT_HS256_FALLBACK_SECRET` to that service's `SECRET_KEY`. A `kid` missing from `jwks_kids` means the pinned document is stale. When `DEBUG=true`, the 401 detail also includes the PyJWT exception name.

On startup the process logs `Identity JWKS auth ready` with the source, key count, and key ids. A key count of 0, without the HS256 fallback, makes every authenticated call fail.

## WebDAV

WebDAV clients may send `Authorization: Bearer your_access_token_here`, or HTTP Basic where the password is the JWT. The Basic username is not checked. See [WebDAV](clients.md).

## Related

- [Configuration](configuration.md) lists the JWT environment variables
- [Security hardening](security.md) covers production JWT rules
- [Access grants](access.md) uses `company_id` after the token is verified
