# Console protocol

What a Cohen console must implement for `mantis login`, `mantis logout` and `mantis scan`. The API endpoints already exist in the Cohen console; the three OAuth endpoints are new.

Base URLs: console `https://console.snappyfeet.org`, API `https://api.snappyfeet.org`. All OAuth requests are `application/x-www-form-urlencoded`; all responses are JSON.

## 1. `POST /oauth/device/code` (RFC 8628 §3.1)

Request:

| Field | Value |
|---|---|
| `client_id` | `mantis-cli` (public client, no secret) |
| `scope` | `read queue` |
| `device_name` | optional, e.g. `Mantis on build-01` (Cohen extension) |

Response `200`:

```json
{
  "device_code": "<opaque, 32+ random bytes>",
  "user_code": "WDJB MJHT",
  "verification_uri": "https://console.snappyfeet.org/device",
  "verification_uri_complete": "https://console.snappyfeet.org/device?code=WDJBMJHT",
  "expires_in": 600,
  "interval": 5
}
```

Rules:

* `user_code`: 8 characters from an alphabet without look alike characters (`BCDFGHJKLMNPQRSTVWXZ`), shown as `XXXX XXXX`. Case, space and dash insensitive on entry.
* Store only a hash of `device_code`. Bind it to `client_id`, `scope`, `device_name`, creation time and the requester's IP.
* `verification_uri` must be on the console host; Mantis refuses any other host.
* Rate limit per IP.

## 2. `GET /device` (console page, signed in)

* Requires the normal console session; redirect to Google sign in first if needed, then back.
* With `?code=`, prefill the code but still require a click; never approve from the URL alone.
* Show: the code, the device name, the scopes in words ("read verdicts, queue analyses"), the requesting IP's rough location and time, and **Approve** / **Deny**.
* POST with CSRF protection (`deps.check_origin` already does this for console forms).
* Approve marks the device code approved for this account. Deny marks it denied.
* Lock a code after 5 wrong entries.

## 3. `POST /oauth/token` (RFC 8628 §3.4)

Request: `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id=mantis-cli`.

| State | Status | Body |
|---|---|---|
| Waiting for the user | 400 | `{"error":"authorization_pending"}` |
| Polled faster than `interval` | 400 | `{"error":"slow_down"}` (Mantis adds 5 s) |
| Denied | 400 | `{"error":"access_denied"}` |
| Expired | 400 | `{"error":"expired_token"}` |
| Approved | 200 | `{"access_token":"cohen_live_...","token_type":"Bearer","scope":"read queue","expires_in":7776000}` |

On approval, mint an ordinary API key exactly as `POST /keys` does today (same checksum, same HMAC storage under `KEY_PEPPER`, scopes intersected with the plan's scopes, lifetime from the plan), named after `device_name`. Then invalidate the device code: a second exchange must return `expired_token`. The key appears on the Keys page like any other and can be revoked there.

## 4. `POST /oauth/revoke` (RFC 7009)

Request: `token`, `token_type_hint=access_token`, `client_id=mantis-cli`.

Revoke the key if it exists. Always answer `200` with an empty body, including for unknown tokens.

## 5. API endpoints Mantis uses (existing)

| Call | Scope | Use |
|---|---|---|
| `GET /api/key` | any key | Verify the key after login; `whoami` |
| `POST /api/package/npm` | `queue` today | Bulk check, body `{"versions":[...], "queue_unknown": bool}`, headers `Idempotency-Key`, `X-Project`, `X-Client: mantis/<v>` |

### Bulk check scopes

`POST /api/package/npm` accepts any key with `read` when `queue_unknown` is `false`. On a plan with a daily lookup cap, each package counts as one lookup, charged all at once and only if the whole tree fits in what is left today; otherwise `429 daily_cap` and nothing is charged. `queue_unknown: true` needs `queue`. Mantis never retries `daily_cap` or `allowance_spent`, and with `--analyze` it reads `GET /api/key` first so a read only key is refused before spending lookups.

The reference implementation is `app/routes/device.py` in the Cohen console (`cohen-auth`).

### Scans

* Every bulk request after the first in one run sends `X-Scan-Id: <scan id from the first response>`; the console adds it to that scan. The queue pass of `--analyze` also sends `X-Scan-Phase: queue`, so versions counted as unknown move to queued instead of being counted twice.
* `GET /api/scan/{id}` (never metered) gives each job's state, phase, verdict, progress and ETA. Mantis polls it every 20 s while watching.
* `POST /api/scan/{id}/cancel` withdraws the scan's analyses that have not started and refunds them. A job another account also waits on keeps running for them.
* Mantis reads `results[]` from the bulk response: `state` (done, unknown, queued, skipped, unavailable), `known_malware` with `sources`, `vulnerabilities`, `reason`, `queue_position`, `eta_seconds`, `osv_checked`. `unavailable` is never treated as clean.
