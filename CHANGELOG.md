# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.3.0] — 2026-10-12

### Security
- **Adding a passkey needs the phone.** `RelayHandler`'s `/passkey/register/options` used to hand out
  registration options to anyone holding your app's session, and a passkey approves requests on its
  own, so a stolen session cookie could become a permanent second factor. For a user with a linked
  phone the route now answers the same two-phase step as `/login` (202 with the number to show; the
  user approves a `PASSKEY_ENROLL` request on the phone) and returns the options only after that
  approval, once. Users without a linked phone are unchanged. The TouchQue API enforces this too:
  `$tq->webauthn->registerOptions` takes the approved request id as its third argument `$approvalRequestId`.
- **Passkey delete needs the user.** The API now refuses `DELETE /webauthn/credentials/{id}` without
  `externalUsername`: `$tq->webauthn->deleteCredential($id, $externalUsername)`.

### Fixed
- **Waiting on an approval no longer hits the rate limit.** Each browser poll of `/login` counted against
  the per-user limit (5 a minute), so a user who took more than about 7.5 s to approve got a 429 while
  the push was still on the phone. A poll that carries a valid, still-waiting token only reads the
  status and now has its own per-IP budget; new attempts are counted as before.

### Added
- The waiting step carries `telemetryToken` when the workspace collects behavioural signals, so
  `@touchque/web` can send them (pass `telemetry: { apiBaseUrl }` to `touchqueFetch`). Before, the token
  never reached the browser and the bot and browser signals never ran for SDK integrations.

## [3.2.1] — 2026-10-11

### Security
- **The pre-auth relay no longer hands out a first-time linking QR.** `RelayHandler`'s `POST /login` used to answer
  an unlinked user with a linking QR code and recovery codes for whatever username was typed.
  Anyone could scan that QR first and link their own phone to someone else's account. Now it
  answers `{ state: 'enroll' }` without a QR unless `getLoginUser` is set, i.e. unless the route
  only runs after your own password step. Linking from a signed-in page (`/enroll/start`, the
  step-up guard) is unchanged. Your own guards can opt out with the new last argument `$enroll = false` of `Guard::run`.

## [3.2.0] — 2026-10-11

### Added
- **`ApprovalProof::verify($proof, [...])`** — check the phone's own signature over the request,
  action, number-match code and details it showed, without trusting TouchQue (same as the Node SDK's
  `verifyApprovalProof`). Fails closed without `expectedPublicKey` unless `allowUnpinnedKey` is true.
  Needs ext-openssl. Tested against `fixtures/approval-proof-vectors.json`, shared by all SDKs.
- **`$tq->login->reportFraud($requestId, $reason, $note)`** — report a request you later learned was
  fraud (chargeback, account takeover, social engineering). TouchQue's risk engine uses it as its
  strongest training signal; the request's status does not change. Idempotent.
- **Relay routes (`TouchQue\Relay\RelayHandler`)**, the PHP port of the Node SDK's `touchqueRouter`: the 14 routes
  `@touchque/web` calls (`POST /login`, enrollment, offline QR / codes, passkey sign-in, approval and management),
  framework-agnostic, returning a `RelayResponse`. Same security rules as Node: auth-required routes answer
  `401 UNAUTHORIZED_FOR_2FA` without a user; `getLoginUser` binds `/login` and the offline routes to the user who
  passed your first factor (`401 FIRST_FACTOR_REQUIRED`), and the offline routes are off
  (`403 OFFLINE_REQUIRES_FIRST_FACTOR`) until it or `allowOfflineWithoutFirstFactor` is set; `/enroll/start` never
  replaces a linked phone (`409 already_linked`); `/login` uses the guard's two-phase contract; sessions open only
  for the user TouchQue returns; relay errors forward only TouchQue's error code (`502 relay_error` for 5xx /
  network failures).
- **Built-in rate limiting** for the pre-auth routes (`FixedWindowLimiter`: 20 per IP and 5 per username per route
  per minute, `429 RATE_LIMITED` + `Retry-After`) with pluggable storage (`RateLimitStore`; the default
  `MemoryRateLimitStore` only helps in long-running workers, so use APCu/Redis under PHP-FPM).
- **Laravel adapter `TouchQue\Laravel\TouchQueRelay`**: `TouchQueRelay::routes($router, 'touchque')` registers the
  routes on a controller (route-cache safe); `onAuthenticated` gets the Laravel request (session) and the pending
  response.

## [3.1.0] — 2026-09-30

### Security
- **A phone-side reject kills the offline QR.** `offline->challenge(..., $requestId)` and
  `verifyTotp(..., $requestId)` tie the QR / time-based code to the push it follows. Once the phone REJECTS the push,
  no new QR is issued for that sign-in (`409 request_rejected`) and no code — QR or time-based — finishes it
  (`reason` = `request_rejected`). The guard links the QR
  automatically; while the QR is on screen the guard keeps checking the push, so the page learns about a reject
  straight away (`state: rejected`) — and about an approval, which finishes the action without typing a code.

### Added
- **Number matching on the offline QR.** When the linked push (or `$requireNumberMatch`) uses number
  matching, `challenge()` returns `challengeCode` — print it under the QR. The phone shows it among two decoys
  after scanning and the user taps the match; the phone is never told which is right, so a wrong tap yields a code
  that fails verification. The guard's offline step carries it as `offline.challengeCode`.

## [3.0.0] — 2026-09-29

### Security
- `Webhook::verify()` rejects a webhook whose signed `timestamp` is missing or
  unparseable (previously the freshness check was silently skipped).
- New optional `ReplayCache $replayCache` argument (`TouchQue\Webhook\ReplayCache`;
  implement it over Redis/APCu/DB — `MemoryReplayCache` only helps in
  long-running workers): a second delivery of the same `jti` throws
  `TouchQueWebhookReplayException` (a subclass of
  `TouchQueWebhookSignatureException`) — answer 200 to it, it is a duplicate.

## [2.0.0] — 2026-09-28

### Added
- `new TouchQue()` with no arguments reads `TQ_API_KEY` / `TQ_API_SECRET` /
  `TQ_API_URL` from the environment.
- `$tq->start()` / `$tq->check()` / `$tq->complete()` — the headless step-up
  flow: start an approval, get back a JSON-safe "step" (the matching number,
  the enrollment QR, or a `blocked`/`frozen`/`rate_limited` refusal) to
  render in your own UI, and complete an approved request exactly once.
- `TouchQue\Laravel\TouchQueMiddleware` (alias it as `touchque`) — one line
  per protected route, built on `TouchQue\Guard::run()`. The matching number
  is now available **before** approval (previously only `Login::request()`'s
  raw response carried it, with no framework support for relaying it to the
  browser, so number matching could not be completed through a one-line guard).
- `$tq->offline` (`challenge`, `verify`, `verifyTotp`) and `$tq->actions`
  (`define`, `list`) — previously only in the Node SDK.
- `TouchQueAPIException::getStatus()` / `getErrorCode()` / `getReason()` /
  `getAttemptsLeft()` / `getRetryAfter()`; a network failure now throws
  `TouchQueNetworkException` instead of being indistinguishable from a real
  API error.
- `TouchQuePasskeyRequiredError`, thrown by `Login::verify()` when a
  phishing-resistant policy requires a passkey.
- `WebAuthn::deleteCredential($id, $externalUsername = null)` — scope a
  deletion to one user (previously any credential id your key could reach
  was deletable).
- `Login::consume($requestId)` — uses an approved request exactly once.

### Changed
- **Breaking:** default `baseUrl` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, has no DNS record and
  was unreachable).
- **Breaking:** `Config` now throws `TouchQueConfigException` (not
  `\InvalidArgumentException`) for invalid/missing configuration.
- **Breaking:** `Login::verify()` now throws `TouchQueTimeoutException` (not
  `TouchQueRejectedException`) when a request expires unapproved, and
  returns `requestId` / `challengeCode` / `assurance` / `confirmedVia`
  alongside `approved` / `status`.
- Request signing now covers the query string (`GET`/`DELETE` with parameters).
- Optional trailing `?array $details` on `Login::request()` / `Login::verify()`:
  transaction context shown on the mobile approval screen
  (`['Amount' => '1,250.00 USD']` or a list of `['label' => ..., 'value' => ...]`).
  The API rejects out-of-limit values with a 400 (at most 8 entries, labels
  <= 40, values <= 120 characters) rather than truncating them.

## [1.3.0] — 2026-09-06

### Added
- **`WebAuthn` resource** (`$tq->webauthn->...`), parity with the Node SDK:
  `registerOptions`, `registerVerify`, `authenticateOptions`, `authenticateVerify`,
  `primaryOptions`, `primaryVerify`, `listCredentials`, `deleteCredential`.
- **`Auth::getUser(string $externalUsername)`** — user link status, no push.
- `Login::request` / `Login::verify` gained `clientIp`, `userAgent`,
  `requireBiometric`, `requireNumberMatch` (were missing vs Node/Python/Go).
- `HttpClient::delete()` for `deleteCredential`.

### Changed
- `curl_close()` is now skipped on PHP >= 8.0 (no-op + deprecation warning there;
  still called on 7.4).
- Version aligned to `1.3.0` across the server SDK line (node / go / php / python).

### Note
- The `telemetryToken` login-response field flows through untouched (responses
  are associative arrays) — documented in the README's behavioral section.

## [1.1.0] — 2026-08-22

### Changed
- **Breaking:** Composer package renamed from `touchque/php-sdk` to
  `touchque-authenticator/php-sdk` to reflect that this SDK is scoped to the
  TouchQue Authenticator (2FA/MFA) product specifically. The PHP namespace
  is unchanged (`TouchQue\`) — no code changes needed beyond the
  `composer.json` require line.

### Added
- `Auth::validateSecret(string $secret): array` — was already present in the
  Node/Python/Go SDKs, missing here. Closes a real cross-language parity gap.
- `Login::approveWithRecoveryCode(string $requestId, string $code): array` —
  same parity gap, now closed.
- First real automated test suite (`phpunit`, 15 tests covering `Config`
  validation, `Auth`, `Login` including its polling `verify()`, and
  `Webhook`). Note: `Http\HttpClient` itself uses raw `curl_*` functions and
  is not mockable without a refactor — that refactor is out of scope for
  this release; its behavior is exercised indirectly through the resource
  tests, which mock `HttpClient` itself.
- `LICENSE` (MIT) file, matching the license already declared in
  `composer.json`.

### Fixed
- A PHP 8.5 deprecation warning in `TouchQueException::__construct()`
  (implicit nullable parameter).

## [1.0.0] — prior to this changelog

Initial public functionality: `Auth` (generateSecret/resetSecret),
`Login` (request/status/verify), `Webhook` (verify).
