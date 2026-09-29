# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
