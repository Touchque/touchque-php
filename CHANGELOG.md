# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [4.0.0] — 2026-10-20 — TouchQue Actions

> 3.6.0 (Never Locked Out) and 3.7.0 ("Why?" case codes) below were not published on their own; they ship in 4.0.0.

### Breaking
- **Action types moved to `$tq->actionTypes`** (`define`, `list`; class `TouchQue\Resources\ActionTypes`).
  `$tq->actions` is now TouchQue Actions. Replace `$tq->actions->define(...)` with
  `$tq->actionTypes->define(...)`.

### Added
- **TouchQue Actions** (`$tq->actions`): your own code at points of the approval pipeline, run by TouchQue in
  a sandbox. See [ACTIONS.md](../ACTIONS.md).
  - `deploy($slug, ['trigger', 'code' | 'template', 'name', 'secrets', 'allowedHosts', 'capabilities',
    'onFailure', 'order', 'enabled', 'activate'])` (idempotent; a version asking for a loosening capability
    answers `deployed => false` with `approval.required` and waits for an admin's phone approval), `list`,
    `get`, `version`, `update`, `delete`, `rollback($slug, ?int $version)`. Option keys are camelCase; an
    unknown key throws `TouchQueConfigException`.
  - Developer loop: `test([..., 'eventId' | 'event'])` (one run, nothing sent), `dryRun([..., 'replaces',
    'limit', 'since'])` (replay against recent real decisions), `events`, `logs`, `metrics`.
  - `triggers()`, `templates()`, `renderTemplate($id, $trigger, $params)`; `secrets->set | list | delete`.
- `$context` on `login->request()`, `Steps::start()`, `Guard::run()`, `'context'` on `risk->check()`, and a
  `context` option (or `resolveContext()`) on the Laravel `TouchQueMiddleware`: for your Actions only
  (`event.context`), never shown on the phone.
- **`$onChallenge` on `login->verify()`** (11th argument, then `$context`): with number matching the phone asks for
  a number that `verify()` used to return only after the approval. The callable runs once, right after the request
  is created and before the wait, with `requestId`, `expiresAt` and, when present, `challengeCode`, `reasons`,
  `caseCode`. Show `challengeCode` to the user now; the phone asks for it. Not called when only a passkey can
  approve. Anything it throws is logged with `error_log` and ignored: `verify()` keeps waiting.
- `HttpClient::put()` / `patch()`; an empty body is sent as `{}`.
- **Passkey autofill** (WebAuthn conditional mediation): `$tq->webauthn->primaryOptions()` without a
  username (`null` or `''`) asks for options that accept any passkey of your site, and `primaryVerify` names
  the user the passkey belongs to. `RelayHandler` / `TouchQueRelay::routes` answer `POST
  /passkey/authenticate/options` the same way when the body has no `email`, so `@touchque/web`'s
  `passkeys.autofill()` works with no extra route.

## [3.7.0] — 2026-10-19 — "Why?" case codes

### Added
- **Case codes.** Every approval decision (`login->request`, `risk->check`) now names a short case code
  (`K7P-2QX`). Show it to your user ("Tell your support team: K7P-2QX"); your team opens the decision by it in
  the dashboard (Logs → Look up a case).
  - The `login->request` answer has `caseCode` and, for a step-up, `reasons` (plain English, never a score).
  - `risk->check` returns `caseCode`.
  - `TouchQueAPIException::getCaseCode()` on refusals (blocked, frozen, rate limited, provisional, keys lost).
  - Steps (`start`, `Guard::run`, the relay and the Laravel middleware) carry `caseCode` and `reasons`; the guard
    keeps showing the code while it waits.

## [3.6.0] — 2026-10-19 — Never Locked Out

### Added
- **Never Locked Out.** A user whose phone is lost, dead or replaced moves to a new phone without a help desk:
  colleagues they named vouch on their own phones, then a cooling-off anyone can veto.
  - `$tq->recovery->setVouchers($user, $vouchers)` and `$tq->recovery->vouchers($user)` (who can vouch today and why
    not; new `TouchQue\Resources\Recovery`). Ask for the user's phone before you change the list.
  - `$tq->recovery->start(['externalUsername' => ..., 'clientIp' => ..., 'displayName' => ..., 'fallbackVouchers' => [...],
    'required' => ..., 'coolOffMinutes' => ..., 'details' => [...]])` returns the recovery with `bindUri` (show it as a
    QR for the new phone); `status($id)`, `list(['externalUsername' => ...] | ['open' => true])`, `veto($id, $by, $reason)`,
    `Recovery::isOpen()`. Options are camelCase; an unknown key throws `TouchQueConfigException`.
  Only after your first factor (password, IdP). The risk engine's BLOCK refuses; hard signals add a voucher and
  double the cooling-off. Errors carry `code`: `not_enough_vouchers` (with `required`, `eligible`, `vouchers`),
  `recovery_in_progress`, `blocked`, `frozen`, `rate_limited`, `device_not_linked`. After a vouch move, critical
  actions answer 403 `blocked` / `recovery_probation` for 24 h. New webhook events `RECOVERY_STARTED`,
  `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`,
  `RECOVERY_FAILED`; `DEVICE_LINKED` can carry `via: 'recovery'`.
- `details` / `noticeDetails` on start: what the vouchers' phones and the old phone show, in your words (default
  English lines otherwise).
- Approval requests on the phone carry `expiresAt` (a vouch stays open for 10 minutes).

### Changed
- Phone-to-phone transfers must be signed by a phone with a hardware key (the apps do since this release) and move
  only the accounts the phone chose.
## [3.5.0] — 2026-10-18 — Silent sign-ins

### Added
- **Silent sign-ins.** Stop asking the phone again and again when nothing about a sign-in is new. TouchQue's
  risk engine decides; the push is skipped only when it says so.
  - `$tq->risk->check(['externalUsername' => ..., 'type' => ..., 'clientIp' => ..., 'userAgent' => ..., 'browserProof' => ...,
    'maxAgeSeconds' => ...])` returns `['prompt', 'reasons', 'assurance', 'silentMode']` (new `TouchQue\Resources\Risk`,
    options are camelCase; an unknown key throws `TouchQueConfigException`). Sends nothing to the phone. Read
    fail-closed: `prompt` is `false` only when the API answered the boolean `false`; malformed `reasons` become `[]`,
    a missing `assurance` is `normal` (`Risk::parseCheck()`).
  - `$tq->risk->browsers(['externalUsername' => ...])` and `$tq->risk->forgetBrowsers(['externalUsername' => ...,
    'thumbprint' => ...])`: the browsers TouchQue knows for a user, and forgetting one or all of them.
  - `$browserProof` as the last argument of `$tq->login->request()`, `$tq->login->verify()`, `$tq->start()` and
    `Steps::start()`: the browser's device-bound key proof (`X-TouchQue-Browser`, made by `@touchque/web` 1.4.0),
    passed through untouched; once the request is approved, TouchQue knows that browser.
  - `silentSignIn` option (default off) on `TouchQueMiddleware` (constructor option or `protected $silentSignIn`),
    `RelayHandler` / `TouchQueRelay` (POST /login) and `Guard::run()` (new last arguments `$browserProof`,
    `$silentSignIn`): a new attempt carrying the `X-TouchQue-Browser` header is checked first; `prompt: false`
    approves it at once with no push (`assurance.method` `silent`, `confirmedVia` `SILENT`, `requestId` `silent`,
    `reasons`; `onAuthenticated` gets `'via' => 'silent'`). Otherwise, and on any error in the check, the usual push
    starts with the proof attached. `['maxAgeSeconds' => int]` sets your own limit on the age of the last phone approval.
  - `Guard::BROWSER_HEADER` (`x-touchque-browser`), `Guard::silentInputFromHeaders()`.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), TouchQue can move the request to a passkey, refuse it, or approve it as provisional.
  The approval array from `Steps::complete()` and `$tq->login->verify()` carry `provisional`, `revoked`, `revokeReason` and
  `reconfirmedAt`: a provisional approval lets the user in, but TouchQue refuses their critical actions
  (`blocked` / `provisional`) until the phone re-confirms it after the call.
- `Webhook::REASON_*` and `Webhook::EVENT_*` constants for the webhook reasons (`vishing_suspected`, `phishing_origin`,
  `user_reported_coached`, and the existing ones) and events (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and
  the existing ones).
- **Mirror Alarm.** The first waiting step carries `$step['canary']`; `@touchque/web` 1.3.0 loads it on the page
  that shows the sign-in, so a real-time phishing proxy gets the approval refused (`phishing_origin`). Allow
  the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`$tq->login->verify()` throws `TouchQuePasskeyRequiredError` (`$e->reason === 'step_up'`) when a poll shows the request now needs a passkey** (PENDING with
  `requiresPasskey`), instead of polling into a timeout. Finish it in the browser with `@touchque/web`. The
  error has a new `$reason` property (`policy` for the passkey-only policy, as before).
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code TouchQue refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

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
