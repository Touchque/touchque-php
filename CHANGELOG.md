# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.2.0] — 2026-11-13

### Added
- **`Guard::run(null, ...)` uses the default client, `Guard::defaultClient()`:** the client given to the new `Guard::setDefaultClient(?Touchque)`, else a Laravel binding of `Touchque` (`$app->bind/singleton(Touchque::class, ...)`, resolved on each call; a contextual binding for `TouchqueMiddleware` is not used), else one built from `TQ_API_KEY` / `TQ_API_SECRET` (and `TQ_API_URL`) on the first request that needs it and kept once built; a failed build is tried again on the next request. While none can be built the guard answers 500 `misconfigured` (401 `unauthenticated` without a user), logged once per process through Laravel's logger in a Laravel app; `TouchqueMiddleware` shares that one log line. `Guard::isStatusPoll(null, ...)` takes it too and is false while it cannot be built. So a handler needs no client built at startup, where it would throw without keys.
- **`Guard::setDefaultClient(?Touchque $client)`** gives the null path your own client (your `Config`: a logger, a base URL); `null` forgets it: the next call uses your Laravel binding of `Touchque`, else builds from the environment. **`Guard::defaultClient()`** is the fail-fast check at startup: it throws `TouchqueConfigException`, naming what is missing.
- **`Guard::response(array $result, ?callable $errorBody = null, ?Touchque $client = null): array`** gives `['status' => int, 'headers' => array, 'body' => mixed]` for a result that is not an approval, exactly as `TouchqueMiddleware` and the relay send it (both use it now): `Cache-Control: no-store`, `Retry-After` on 423 / 429, `X-Touchque-State` / `X-Touchque-Reason` on 400 and above, and the optional `$errorBody` with the 5.1 rules. A callable that throws, or a result that cannot be encoded, is logged through `$client`'s logger (else Laravel's logger in a Laravel app) and the default body sent. It throws `InvalidArgumentException` for an approval.

### Fixed
- `TouchqueMiddleware`'s answers shaped by `errorBody` keep `getOriginalContent()` (the body), like its other answers and any Laravel `JsonResponse`; a `null` from `errorBody` is still sent as `null`.

### Changed
- **Waiting polls carry `expiresAt`.** A `waiting` or `passkey_required` step with `expiresAt` puts it in its token (claim `rx`, ms since the epoch), and every later answer for that request in those two states carries `expiresAt`: the live one from Touchque's status answer when it has one (a push moved to a passkey during a call gets 180 s more), else the token's. The new token keeps the value used, and the offline QR next to the push carries it on. Only the first answer had it, so a page reading it from the latest answer never stopped by time. `Steps::check()` gives the live `expiresAt` while a request waits. With neither, polls answer as before.
- **`$enroll = false` says why.** A user with no phone on a guard that may not show the linking QR gets 202 `{"touchque":{"state":"enroll","reason":"enrollment_off"}}` instead of a bare `enroll` step: the relay's `POST /login` without `getLoginUser` and its passkey registration too. `@touchque/web` 2.2.0 stops polling on it.
- README: "Guard inside your handler" uses `Guard::run(null, ...)` and `Guard::response()`, shows `Guard::setDefaultClient()` and the fail-fast `Guard::defaultClient()`, says that a new first-time QR comes about 15 s before the old one expires with new recovery codes (the old QR and codes stop working) and that a first-time QR poll is charged once the QR is gone or within about 15 s of expiring, that waiting polls carry `expiresAt`, what `enrollment_off` means, and that `passkey_required`, `offline` and an `enroll` step with a reason need `@touchque/web` or your own UI following the contract. The examples run on PHP 7.4: no named arguments (`new Config(null, null, null, 10000, $logger)`, the code reply's 20th argument).

## [5.1.0] — 2026-11-12

### Fixed
- **The first-time QR stays the same while the user scans it.** Every poll with an `enroll` token started again (login request, 404 `device_not_linked`, generate-secret 409, reset), so each 1.5 s poll replaced the QR and the recovery codes on screen and the QR being scanned stopped working. Now:
  - The enroll step carries `enroll.expiresAt`: the API's `expiresAt` when it is ISO 8601, else now + its `ttlMs`; its token carries that expiry.
  - A poll with that token reads only the link state (`GET /users/{externalUsername}`). Not linked, with more than 15 s left: 202 `{"touchque":{"state":"enroll","expiresAt":"..."},"token":"..."}` with no `enroll` object, so the page keeps the QR and the recovery codes it shows; no new secret, no push. Linked: the push starts as before. Expired, about to expire, or unknown to Touchque: a new QR comes with `enroll.qrCodeDataUrl`.
  - `Guard::isStatusPoll()` is true for such a poll while the first-time QR is up (more than 15 s before it expires), so the relay's `POST /login` no longer counts those polls against the per-user limit. Renewing an expiring QR still counts.
  - Pages on `@touchque/web` need 2.1.0, which keeps the QR it shows for such a step.
- **A start is always charged.** A first-time QR poll that starts after all (the user linked: the push; the QR expired or is gone: a new QR) calls `Guard::run()`'s new last argument `$beforeStart` first, which may answer instead. The relay's `POST /login` charges it to the username's budget like a new attempt and answers its usual 429 over the limit, so replaying an old enroll token can no longer push on the poll budget.
- **`TouchqueMiddleware` answers JSON when `TQ_API_KEY` / `TQ_API_SECRET` are missing.** It used to throw when Laravel's container built it. The client now comes from the container on the first request, inside the middleware's error handling, and is kept once built. Without keys a guarded route answers 500 `misconfigured` with `Cache-Control: no-store` (401 `unauthenticated` when nobody is signed in) and never runs; the middleware logs once, through Laravel's logger: `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.`

### Added
- **`errorBody`: refusals in your API's own error shape.** `new TouchqueMiddleware(null, ['errorBody' => fn (array $r) => ['message' => $r['message'], 'code' => $r['code']]])`. It is called for every answer of 400 and above (401, 403, 408, 423, 429, 500, 503), never for a 202 step or an approval, with the refusal `['status', 'code', 'message', 'touchque']`. What the result encodes to, as `JsonResponse` encodes it, decides: a JSON object (an array with string keys, an object, a `JsonSerializable`, `Arrayable` or `Jsonable`) is sent with `touchque` set to the step (the SDK's key wins, no `token` is added); anything else as it is. Status and headers stay the same. A callable that throws, or a result that cannot be encoded, is logged (`[Touchque] errorBody failed: <message>`) and the default body sent.
- **Refusal headers.** Every guard answer of 400 and above, from `TouchqueMiddleware` and the relay, carries `X-Touchque-State` and, when the step has a reason, `X-Touchque-Reason`; `@touchque/web` 2.1.0 reads the step from them when the body has no `touchque` key. Cross-origin pages must expose them (`Access-Control-Expose-Headers`). `Guard::headers($result)` gives them, with `Cache-Control` and `Retry-After`, for your own handler.
- `Guard::refusal($result)` and `Guard::errorBody($result, $errorBody)` for the same shape in your own handler; `Guard::unauthenticated()` and `Guard::misconfigured()`, the guard's 401 and 500 answers.
- README: "Guard inside your handler" (`Guard::run()` after your own checks, what to send back, the 202 and first-time QR polls, `$beforeStart` for your own rate limits), the `errorBody` option, the refusal headers and what a missing key answers.

### Changed
- `TouchqueMiddleware`'s client argument is optional: `new TouchqueMiddleware(null, $options)` (the default) takes the client from Laravel's container on the first request, as constructor injection did: a contextual binding (`$app->when(TouchqueMiddleware::class)->needs(Touchque::class)`), your `Touchque` binding, or one from the environment. Passing a client works as before. The README's binding examples use `null`: `$app->make(Touchque::class)` there would still throw without keys.

## [5.0.0] — 2026-11-11

### Breaking
- **Every name is spelled Touchque instead of TouchQue.** The namespace `TouchQue\` is `Touchque\` (Composer autoload `Touchque\\`). The client `TouchQue\TouchQue` is `Touchque\Touchque`, and `TouchQueAgent` / `TouchQueOrgAgent` are `TouchqueAgent` / `TouchqueOrgAgent`. The error classes in `Touchque\Exceptions` lose the capital Q the same way: `TouchQueException` → `TouchqueException`, `TouchQueAPIException` → `TouchqueAPIException`, `TouchQueConfigException` → `TouchqueConfigException`, `TouchQueNetworkException` → `TouchqueNetworkException`, `TouchQueRejectedException` → `TouchqueRejectedException`, `TouchQueTimeoutException` → `TouchqueTimeoutException`, `TouchQuePasskeyRequiredError` → `TouchquePasskeyRequiredError`, `TouchQueWebhookSignatureException` → `TouchqueWebhookSignatureException`, and every other `TouchQue*Exception` → `Touchque*Exception`. The Laravel adapters `TouchQue\Laravel\TouchQueMiddleware` and `TouchQueRelay` are `Touchque\Laravel\TouchqueMiddleware` and `TouchqueRelay` (their constructor parameter `$touchQue` is `$touchque`), and `MyAccount::unlinkTouchQueApp()` is `unlinkTouchqueApp()`. The headers are written `X-Touchque-Token`, `X-Touchque-Offline`, `X-Touchque-Code`, `X-Touchque-Code-Type` and `X-Touchque-Browser`: HTTP header names are case-insensitive, so servers are unaffected, and the SDK reads them case-insensitively as before. Messages and log lines say Touchque. Code using the old names must be updated; nothing else changes. The wire protocol, the routes and the signed EIP-712 type string `TouchQueGovernance(...)` that `SafeApproval` hashes stay as they are.

### Fixed
- `CodeReply::open` calls `openssl_pkey_derive()` without its `key_length` argument, which PHP 8.5 deprecates; P-256 gives the same 32 bytes.

### Changed
- The README links work where the package is read (npm, PyPI, GitHub): the Actions and Touchque Login guides point to support.touchque.com, SECURITY.md and CONTRIBUTING.md to this package's public repository.
- The README has an "Action types" section: define a type once (dashboard → Developers → Action types, or from code); the guard answers 500 `misconfigured` for an undefined name and 403 `action_disabled` for one turned off.
- The README states the real requirement, PHP 7.4+ (it said 8.1+), and composer suggests `ext-sodium` for Ed25519 agent keys.

## [4.2.0] — 2026-11-10

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `agents->verifyApprovalToken($token, $audience = null, $expect)` uses this workspace's own audience by default: `agents->approvalAudience()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `ApprovalToken::verifyWith($token, $jwks, $audience, ...)` requires the audience. A missing or empty one throws TouchqueApprovalMismatchException (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass agents->approvalAudience()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.
- **Hosted login: an empty `iss` is refused too (RFC 9207).** `handleCallback` already refused a callback whose `iss` names another issuer; one with an empty `iss=` now throws `issuer_mismatch` as well, before the code is exchanged. A callback without `iss` (a server that does not send it yet, or `null` for a missing field) is still accepted.
- `SafeApproval::verify` without `purpose` accepts only an ordinary approval (`approve`); check an approval to schedule a governance change with `'purpose' => 'schedule'`. Either one used to pass, so a caller that took `valid` as permission to execute could accept an approval meant to schedule a change, whose governance hash covers no nonce or gas fields.
- `HostedLogin` and `MyAccount` refuse a plaintext `http://` domain except on this machine (localhost, 127.0.0.1, [::1], *.localhost), the rule the API `baseUrl` follows: authorization codes, PKCE verifiers, the client secret and tokens would otherwise travel in the clear.

### Added
- **`deviceRisk->searchEvents([...])`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `from`/`to` (7 days by default, at most 90, within your retention), `signal`, `stepUp`, `kind`, `origin`, `ip` (an address or a CIDR range; never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100) and the opaque `cursor` from the previous page's `nextCursor`.
- `deviceRisk->check()` returns `'engine'` (`?string`): the engine's state for this check; `'unavailable'` when the risk engine could not be reached and the verdict is a safe default (`stepUp` true), so an outage can be told apart from risk.
- **`webauthn->primaryAvailability()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers `['enabled' => bool, 'userVerification' => 'required' | 'preferred' | null]`. Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `primaryOptions` answers 403 `passwordless_login_disabled`.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of Touchque's decision. `(new SecurityEventVerifier(['issuer', 'audience', 'jwksUri'?, 'jwks'?, 'clockSkew'?]))->verify($token)` returns `['jti', 'issuer', 'audience', 'issuedAt', 'txn', 'subject', 'type', 'name', 'claims']` or throws `TouchqueSecurityEventException` with the RFC 8935 code to answer in `->error` (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `SecurityEventVerifier::poll($url, $token, ['ack', 'setErrs', 'maxEvents'])` for poll delivery (RFC 8936); `SecurityEventVerifier::TYPES`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.** `$tq->safeGuard->request($externalUsername, $type, $safeTx, $options)` sends the raw transaction (the phone decodes it itself and signs with a key only its biometrics unlock), `status($requestId)` and `waitForApproval($requestId)` hand back the 105-byte approval. `SafeApproval::verify($target, $approval, $approverKey, ['purpose', 'approverIndex', 'rows' | 'displayDigest', 'now'])` checks it the way the guard does, without trusting Touchque: the Safe transaction hash (EIP-712) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature (ext-openssl). `SafeApproval::withApprovals($ownerSignatures, $approvals)` for `execTransaction`, `SafeApproval::scheduleCall($safe, $governanceHash, $approvals)` for a governance change; `safeTxHash`, `governanceHash`, `message`, `displayDigest`. Pure PHP 7.4 (no gmp or bcmath). Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).
- `$tq->login->waitForApproval($requestId, $timeoutMs = 30000, $pollIntervalMs = 400)`, like the Node SDK's `login.waitForApproval`: polls a request you sent with `request()` until the user answers and returns `['approved', 'status', 'requestId', 'assurance', 'confirmedVia', 'provisional']`; throws `TouchqueRejectedException`, `TouchqueTimeoutException` (expired or out of time) or `TouchquePasskeyRequiredError` (`reason` step_up, Vishing Shield).
- `SecurityEventVerifier` refuses a JWKS URI that is not https (http only on this machine), whether found from `/.well-known/ssf-configuration` or given as `jwksUri`, like every other Touchque SDK: `verify()` throws `TouchqueSecurityEventException` `temporarily_unavailable` and the keys are never fetched.
- Webhook event constants `Webhook::EVENT_MOBILE_PUSH`, `EVENT_RECOVERY_*` (`STARTED`, `DEVICE_BOUND`, `COOLING`, `COMPLETED`, `VETOED`, `EXPIRED`, `FAILED`) and `EVENT_ASSIST_*` (`OPENED`, `ENDED`, `CHECK_PASSED`, `CHECK_FAILED`, `UNFROZEN`, `CLAIM_CONFIRMED`, `CLAIM_UNVERIFIED`), the names the backend sends.
- Shared Signals: tests for discovery through `/.well-known/ssf-configuration` and for `SecurityEventVerifier::poll` against a local transmitter, and a README section "Shared Signals (security events from Touchque SSO)".

### Fixed
- `identity->users->list()`, and every other GET with a boolean parameter, sends `true` / `false` instead of `1` / `0`: the API ignored `['blocked' => true]` and `['emailVerified' => false]` and listed every user.
- `CodeReply::newKey()` returns a PKCS#8 private key on PHP 7.4 and 8.0 too. Before PHP 8.1 the key came out in the SEC1 form and `CodeReply::open()` returned null for every typed-back code.
- Laravel `TouchqueMiddleware`: the details named after the action (`touchque:SEND_MONEY,transferDetails`) now come from a Request macro too; a macro was not seen, so the phone showed no details and the approval was bound to none. A name that is neither a method nor a macro answers 500 `misconfigured` instead of approving without the details.
- `Webhook::verify` accepts a genuine webhook whose values contain U+2028 or U+2029, and one with a decimal number on a host whose `serialize_precision` is not -1: the canonical form now matches the server's `JSON.stringify`.
- A 3xx answer from the API (a wrong `baseUrl`, a proxy that redirects) throws `TouchqueAPIException` instead of passing as an empty success.
- `new Config(..., 'http://[::1]:3000')` is accepted like the other loopback addresses.

## [4.1.0] — not published (these changes ship in 4.2.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `network`, `velocity` and `bot`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.
- **A code typed back on the phone:** `$tq->login->request(..., reply: ['kind' => 'code', 'key' => ..., 'channel' => ..., 'target' => ...])`; `Touchque\CodeReply::newKey()` and `CodeReply::open($privateKey, $requestId, $ct)` open `status()['reply']['ct']`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) throws `TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException` or `TouchqueFeatureOffException`, all `TouchqueFeatureException` (`getFeature()`, `getFeatureReason()`) and still `TouchqueAPIException`.
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`Webhook::EVENT_DEVICE_RISK_*`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `$tq->deviceRisk->check($_POST['touchque_request_id'] ?? null, 'sign_in', $email)`** with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: null, empty, made up or expired is still a verdict (`report`: missing, unknown, expired, invalid; the signal `device_identification_missing`, a number-matched step-up at most), never an exception. `DeviceRisk::REPORTS`.
- **Device risk: `$tq->deviceRisk->check($requestId, $event, $externalUsername, $clientIp)` and `$tq->deviceRisk->getEvent($requestId)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `deviceRiskRequestId` (or `deviceRisk`) on `login->request` and `risk->check`. The page's `requestId` comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`stepUp`, never a refusal); signals start in shadow. `DeviceRisk::parse`, `DeviceRisk::EVENTS`.
- **Pairing a browser by QR code: `$tq->qrPairings`.** `create($keyThumbprint, ['clientIp', 'userAgent', 'browser', 'os', 'ttlSeconds'])` registers a pairing for the browser key your page holds (`@touchque/web` `browserKey.thumbprint()`) and returns `uri` (`touchque://pair-browser?...`) to show as a QR code; the nonce in it stays with you (Touchque keeps its hash). `get($pairingId)` says who scanned it and how near the phone was (`proximity`), `refuse($pairingId, $reason, $message)` tells the phone why your own checks said no. `login->request(..., $qrPairing)` (the 17th argument) asks the phone that scanned, once, with number matching. `QrPairings::uri()`, `QrPairings::REFUSAL_REASONS`.
- **Touchque Login Management API:** `identity->clients->rotateSecret($clientId)` (the new secret is shown once), `identity->users->endSession($userId, $sessionId)` signs the person out of one session, `identity->exports->file($jobId)` returns the finished export (CSV or JSON lines) as text.
- **Actions: the `agent.approval` trigger**, before an AI agent's request reaches the phone (`'trigger' => 'agent.approval'`); only tightening counts: `api.deny`, `api.requirePasskey`, `api.stepUp`. See ACTIONS.md.
- **Webhook reason `user_blocked_agent`** (`Webhook::REASON_USER_BLOCKED_AGENT`): the person rejected an AI agent's request with Block this agent on their phone; the agent may not ask them again, and 2FA is not frozen. `listBlocks` can return the block reason `'phone'`.
- **AI agents: events for a SIEM.** `agents->listEvents($after, $since, $limit)`: the workspace's agent events (`AGENT_*`, `AGENTS_*`) oldest first, each with its agent, person, approval and case code; keep `next` and pass it as `$after`.
- **AI agents: the workspace's policy and a passkey line.** `agents->getWorkspacePolicy()` / `setWorkspacePolicy($policy)`: every agent's floor (an agent's own policy can only be stricter, field by field). `requirePasskeyAbove` (['TRY' => '10000.00']) in any policy: over it the person approves with a passkey on your page (`requiresPasskey` on the approval), never on the phone or with a mandate; a background request gets 409 `interactive_required`. `Webhook::EVENT_AGENT_WORKSPACE_POLICY_CHANGED`. A second approver who answers sooner than a person can gets no token (status `blocked`, reason `inhuman_approval`).
- **Touchque Login: the approving app's name and custom-domain-only sign-in.** `identity->setApproverAppName($name)`: the phone app the hosted pages tell customers to approve on ("Approve on the Acme app"; `null` = your brand when the Mobile SDK is set up, else Touchque). `identity->setCustomDomainOnly(true)`: serve sign-in only on the primary custom domain ({slug}.login.touchque.com redirects page loads there and refuses other calls; needs a verified primary domain with a working certificate). `identity->checkDomainCertificate($domainId)`: the domain's certificate at the sign-in edge now (`certificate`: pending, active or error).
- **Cross App Access (ID-JAG) and A2A agent cards.** `CrossAppAccess::requestIdJag` trades a member's ID token for an ID-JAG at the organization's identity provider, `redeemIdJag` trades it for an access token at the other service (jwt-bearer); `IdJagVerifier` checks one at your own authorization server (typ, issuer, single audience, client, expiry, used once; `firstUse` for a shared store). `AgentCard::verify` checks an A2A card's signatures (JWS over the RFC 8785 canonical card; `jku` only on the card's host or `trustedJkuHosts`), `sign`, `canonicalJson`.
- **Security-change lock, look-alike destinations, Second Thought questions — for any action type.** `login->request()` and `verify()` take `$securityChanges` (['password' | 'mfa' | 'device' | 'email' | 'phone' => DateTimeInterface, ISO 8601 or epoch ms], when each last changed in your system): access rules and Actions read `minutesSince.mfaChange`, `.deviceChange`, … (e.g. refuse `PAYOUT_CHANGE` within 24 h of a 2FA change). `$destination` (['kind' => 'iban' | 'account' | 'wallet' | 'address' | 'payee', 'value' => ..., 'known' => [...]]) is shown in full on the phone in groups of four, with a warning when it looks like one the user used before but is not the same; the answer's `destination` is ['known', 'lookalike'], rules read `destination.lookalike`. `$locale` ('tr' | 'en') for those rows. `actionTypes->define($type, $name, $description, $critical, ['questions' => [...], 'locale' => ...])` (at most two of `ActionTypes::SECOND_THOUGHT_QUESTIONS`, `['questions' => []]` turns them off): the phone asks them before Approve and a risky answer makes the approval `provisional`.
- **Mobile SDK: your own app approves for your users.** `$tq->mobile->createEnrollment(['externalUsername' => ..., 'replace' => ..., 'ttlSeconds' => ...])` gives a one-time `tqe_` token your iOS/Android app spends with the Touchque Mobile SDK; `listDevices()`, `getDevice()`, `removeDevice()`, `settings()`, `updateSettings()`. `Mobile::pushFromWebhook($event)` turns the signed `MOBILE_PUSH` webhook into the APNs payload / FCM data you send with your own keys; `Mobile::isPushExpired()`.
- **Mobile SDK: Touchque can send the push.** `updateSettings(['apns' => [...], 'fcm' => ['serviceAccount' => ...]])` gives Touchque your own APNs key / Firebase service account; it then pushes that platform itself instead of the `MOBILE_PUSH` webhook (`null` removes a key). `settings()['push']` shows who pushes, never the keys. `updateSettings(['androidCerts' => ...])`: the SHA-256 of each Android app's signing certificate, checked against Key Attestation at enrollment. `mobile->testPush($deviceId)` sends a harmless push the way a request would reach the phone and says which way it went and whether APNs / FCM took it; a `MOBILE_PUSH` webhook may now have `kind` `test`.
- **`clientSignals` on `login->request()` (last argument) and `risk->check()`:** the end user's page check from `@touchque/web`; a browser driven by software is never silent and asks with number matching, or is refused where the workspace blocks it.
- **Help desk.** `$tq->assist->open(['externalUsername' => ..., 'agent' => ['name' => ..., 'title' => ..., 'ref' => ...]])` before your help desk acts on someone's account (their phone gets a calm notice; their "someone says they're from IT" button shows the agent), `verify($id, $action)` before a sensitive action (a 2-digit `challengeCode` the agent reads to the person, who types it and approves on their phone; `no_phone` routes to Never Locked Out), `spend($id, $requestId, $action)` right before the action, `unfreeze()`, `get()`, `list()`, `end()`; `Assist::checkPassed($session, $requestId)`. Webhooks `ASSIST_*`, among them `ASSIST_CLAIM_UNVERIFIED` (someone pretended to be IT).
- **Touchque Login: an app acting for a customer.** `$login->exchangeToken($userAccessToken, $audience, $scope)` (RFC 8693), `$login->askUser($loginHint, $scope, $options)` and `$login->waitForUser($ask)` (CIBA, poll mode); token arrays gain `authorizationDetails` and `issuedTokenType`.
- **Touchque Login: token vault.** `$login->getConnectionToken($userAccessToken, $connection, $scope)` returns the provider's own access token (Google, Microsoft, GitHub…) for the signed-in customer from a connection that stores tokens (`options.tokenVault`); Touchque refreshes it and the refresh token never leaves (token arrays gain `connection`; `HostedLogin::CONNECTION_TOKEN_TYPE`). `identity->users->connectedAccounts($userId)` and `disconnectAccount($userId, $accountId)`; My Account `stopAppAccess($id)` and `identities[].appAccess`.
- **`$expiresIn` on `login->request()`** (last argument): how long the push waits for the person, 30 (default) to 300 seconds, for requests the person has to read first.
- **`McpAuth` for MCP servers whose authorization server is Touchque SSO** (Organization → MCP servers). `new McpAuth(['issuer' => ..., 'resource' => ..., 'tools' => [...]])`:
  `protectedResourceMetadata()` at `metadataPaths()` (RFC 9728), `verify($method, $url, $headers)` (Touchque's JWKS, issuer,
  audience = this server, expiry, DPoP proof for a bound token), `requireTool($claims, $tool)` (403 `insufficient_scope` with the scope).
  `TouchqueMcpAuthException` carries `$status` and `$wwwAuthenticate`.
- **Attack protection in `$tq->identity`:** `getAttackProtection()`, `setAttackProtection()`, `attackEvents()`.
  Actions accept the Touchque Login triggers (`identity.post_login`, …).
- **Email and SMS providers in `$tq->identity`:** `getDelivery()`, `setDelivery($channel, $provider)`,
  `removeDelivery($channel)`, `testDelivery($channel, $to)`. **My Account:** `startSmsEnrollment()`,
  `verifySmsEnrollment()`, `removeSmsCodes()`.
- **Touchque Login My Account API.** `$login->myAccountToken($refreshToken, $scope)` trades a first-party app's
  refresh token for a `https://<domain>/me/` token (keep the rotated refresh token); `$login->myAccount($accessToken)`
  returns `MyAccount` (get, updateProfile, authenticationMethods, removePasskey, unlinkTouchqueApp, setEmailCodes,
  unlinkIdentity, setPassword, removePassword, changeEmail, sessions, endSession, endOtherSessions, apps,
  revokeApp, consents, setMarketing, exportData, deleteAccount). A too-old sign-in throws `MyAccountException`
  with `isStepUp()`. `$login->accountUrl($section)` links the hosted account page.
- **Touchque Login Management API: `$tq->identity`.** `users` (list/search, get, create with a password, a
  bcrypt/argon2 `passwordHash` or a `customPasswordHash`, update with merged metadata, block, unblock, delete
  (KVKK/GDPR erasure), export, sessions, signOutEverywhere, resetMfa, unlinkIdentity, sendVerificationEmail,
  passwordReset, addRoles, removeRole, logs), `imports` and `exports` (start, get, wait), `roles`,
  `organizations` (members, connections, invite), `clients`, `apis`, `connections`, `customDomains`, and the
  tenant (getTenant, updateTenant, rotateSigningKey, outbox).
- **Touchque Login (hosted sign-in) for your app.** `Touchque\HostedLogin\HostedLogin` is an OpenID Connect client
  for your tenant (`acme.login.touchque.com` or your own domain): `authorizationUrl()` (PKCE S256, state, nonce,
  `screenHint`, `loginHint`, `uiLocales`, `connection`, `organization`, `maxAge`, `acrValues`), `handleCallback()`
  (state and `iss` checks, code exchange, ID token verified against the JWKS with ext-openssl: signature, issuer,
  audience, expiry, nonce, `at_hash`), `refresh()`, `clientCredentials()`, `revoke()`, `userinfo()`, `logoutUrl()`, and
  `verifyAccessToken()` for your API.
- **AI agents as identities of their own.** `$tq->agents` registers an agent with its PUBLIC key, an accountable
  owner, the action types it may ask approvals for and a review date (`create`, `list`, `get`, `update`, `addKey`,
  `removeKey`, `suspend`, `resume`, `revoke`, `setKillSwitch`). `Touchque\TouchqueAgent` is the agent side: its own
  key (private_key_jwt, RFC 7523), a 10-minute token bound to that key with DPoP (RFC 9449), never your API key.
  `AgentKeys::generate('ES256' | 'EdDSA')`, `AgentKeys::thumbprint()`. ES256 uses ext-openssl, EdDSA ext-sodium.
- **Agent policies and people who stopped an agent:** `$tq->agents->setPolicy($id, $policy)`, `listBlocks($id)`, `liftBlock($id, $user)`.
- **Agents ask people to approve on their phone.** `$agent->requestApproval($user, $type, $authorizationDetails, $options)`,
  `$agent->waitForApproval($id)` (approval token or `TouchqueApprovalException`), `$tq->agents->redeemApproval($token, $expect)`
  (checked before anything is used, then used exactly once; `TouchqueApprovalMismatchException`),
  `$tq->agents->verifyApprovalToken()` and `ApprovalToken::verifyWith()` offline, `ApprovalToken::matches()`.
- **Four eyes and mandates.** `fourEyes` in the agent policy (a second approver on their phone; `awaiting_second`
  keeps `waitForApproval` waiting). `$agent->requestMandate($user, $type, $maxCount, $maxTotal, $options)`,
  `getMandate()`, `revokeMandate()`; `requestApproval(..., ['mandateId' => …])` is approved within the mandate
  without a push. `$tq->agents->listMandates($id, $user)`, `revokeMandate($id, $mandateId)`.
- **What Touchque notices about an agent.** Refusals carry the case code; new codes `suspicious_content` (400, `markers`),
  `interactive_required` (409), `name_too_similar` (409 on create/update, `similarTo`); an approval answered faster than a
  person ends `blocked` with reason `inhuman_approval`. `Webhook::EVENT_AGENT_*` names every agent event.
- **Organization AI agents on Touchque SSO: `Touchque\TouchqueOrgAgent`.** DPoP-bound tokens for one of the organization's
  apps with its own key or its platform's token (`TouchqueOrgAgent::githubActionsToken('touchque')`, `fileToken($path)`):
  `getToken(['resource' => …, 'scope' => …])`, `authorization($method, $url)`, `dpopProof()`.
- **An organization's agent acts for a member.** `exchangeToken($subjectToken, $options)` (RFC 8693),
  `askMember($loginHint, $options)` and `waitForMember($request)` (CIBA, poll mode).
- **An organization's agent uses a member's own account elsewhere (token vault).** `$agent->getConnectionToken($subjectToken, $connection, $scope)`: the member's own access token at Google, Microsoft 365, GitHub, Slack, Salesforce or any OAuth 2.0 service they connected on Touchque (portal `/connections`), for a connection that names the agent. A Bearer token for that service; Touchque refreshes it and the refresh token never leaves; `invalid_grant` when the member has not connected it, disconnected or left.
- **An organization's agent asks for a shared account.** `$agent->askToOpenSharedAccount($account, $loginHint, $message)` → `['askId', 'openUrl', 'status', 'expiresIn']`: the member opens `openUrl` where their Touchque extension is paired, their phone approves with the agent named, and the extension signs in there; the agent never sees the password. `sharedAccountAskStatus($askId)` and `waitForSharedAccount($ask)` say only how it ended (`opened`, `refused` with a reason, `declined`, `expired`).
- **Token vault for your agents (`$tq->agents->vault`).** `putConnection($name, ['provider', 'clientId', 'clientSecret', 'tenant', 'issuer', 'agentIds'])` (google, microsoft, github, facebook, linkedin, x, oidc: your OAuth app there), `deposit($connection, $user, ['accessToken', 'refreshToken', 'expiresIn', 'scope'])` after your own OAuth flow with the person, `listConnections()`, `listAccounts($user)` (never a token), `removeAccount()`, `removeConnection()`. The agent: `$agent->getConnectionToken($user, $connection, $scope)` (scope `vault:read`): a fresh Bearer token for that service, refreshed by Touchque; the refresh token never leaves.
- **`$agent->requireApproval($user, $type, $authorizationDetails, $options, $onChallenge, $timeoutSeconds)`:** asks the person's phone and waits in one call (the number shown through `$onChallenge`), for putting in front of any agent framework's tool call.
- **API key scopes are enforced:** a narrower key (for example `login:*`) is refused elsewhere with 403 `insufficient_scope`.
- **`device` on `auth->getUser()`:** the linked phone's posture (platform, model, OS version, security patch, screen
  lock, jailbreak/root, hardware key, attestation, `state`, `issues`), or `null` before a phone is linked. Documented array shape.
- **`$challengeDigits`** on `login->request()` / `login->verify()` (`2` or `3`): the length of the matching
  number when one is shown, `3` for 100–999. The longer of this and your workspace policy wins: a request can
  lengthen the number, never shorten it.
- **Codes during a Touchque outage:** `offline->totpVerifiers()` and `Offline::matchTotpVerifier()`. While
  Touchque answers, fetch salted, slow digests of your users' next time-based codes (up to 4 hours ahead,
  24,000 user-steps a call; never a key); while it cannot be reached, check a typed code against them locally. Needs the workspace
  policies `offlineTotpEnabled` and `outageVerifiersEnabled`; frozen and removed users fall out on the next fetch.

### Changed
- **Silent by default.** Nothing goes to `error_log()` on its own any more: the SDK's own problems (a misconfigured guard, a failed `$onChallenge`, a relay error or a relay without `getLoginUser`) go to `new Config(..., logger: $psrLogger)` (any PSR-3 logger, or a `callable(string $level, string $message)`), or to `error_log()` with `debug: true`; otherwise nowhere.
- `TouchqueApprovalMismatchException` no longer names the other person in its message.

## [4.0.0] — 2026-10-20 — Touchque Actions

> 3.6.0 (Never Locked Out) and 3.7.0 ("Why?" case codes) below were not published on their own; they ship in 4.0.0.

### Breaking
- **Action types moved to `$tq->actionTypes`** (`define`, `list`; class `Touchque\Resources\ActionTypes`).
  `$tq->actions` is now Touchque Actions. Replace `$tq->actions->define(...)` with
  `$tq->actionTypes->define(...)`.

### Added
- **Touchque Actions** (`$tq->actions`): your own code at points of the approval pipeline, run by Touchque in
  a sandbox. See [ACTIONS.md](../ACTIONS.md).
  - `deploy($slug, ['trigger', 'code' | 'template', 'name', 'secrets', 'allowedHosts', 'capabilities',
    'onFailure', 'order', 'enabled', 'activate'])` (idempotent; a version asking for a loosening capability
    answers `deployed => false` with `approval.required` and waits for an admin's phone approval), `list`,
    `get`, `version`, `update`, `delete`, `rollback($slug, ?int $version)`. Option keys are camelCase; an
    unknown key throws `TouchqueConfigException`.
  - Developer loop: `test([..., 'eventId' | 'event'])` (one run, nothing sent), `dryRun([..., 'replaces',
    'limit', 'since'])` (replay against recent real decisions), `events`, `logs`, `metrics`.
  - `triggers()`, `templates()`, `renderTemplate($id, $trigger, $params)`; `secrets->set | list | delete`.
- `$context` on `login->request()`, `Steps::start()`, `Guard::run()`, `'context'` on `risk->check()`, and a
  `context` option (or `resolveContext()`) on the Laravel `TouchqueMiddleware`: for your Actions only
  (`event.context`), never shown on the phone.
- **`$onChallenge` on `login->verify()`** (11th argument, then `$context`): with number matching the phone asks for
  a number that `verify()` used to return only after the approval. The callable runs once, right after the request
  is created and before the wait, with `requestId`, `expiresAt` and, when present, `challengeCode`, `reasons`,
  `caseCode`. Show `challengeCode` to the user now; the phone asks for it. Not called when only a passkey can
  approve. Anything it throws is logged with `error_log` and ignored: `verify()` keeps waiting.
- `HttpClient::put()` / `patch()`; an empty body is sent as `{}`.
- **Passkey autofill** (WebAuthn conditional mediation): `$tq->webauthn->primaryOptions()` without a
  username (`null` or `''`) asks for options that accept any passkey of your site, and `primaryVerify` names
  the user the passkey belongs to. `RelayHandler` / `TouchqueRelay::routes` answer `POST
  /passkey/authenticate/options` the same way when the body has no `email`, so `@touchque/web`'s
  `passkeys.autofill()` works with no extra route.

## [3.7.0] — 2026-10-19 — "Why?" case codes

### Added
- **Case codes.** Every approval decision (`login->request`, `risk->check`) now names a short case code
  (`K7P-2QX`). Show it to your user ("Tell your support team: K7P-2QX"); your team opens the decision by it in
  the dashboard (Logs → Look up a case).
  - The `login->request` answer has `caseCode` and, for a step-up, `reasons` (plain English, never a score).
  - `risk->check` returns `caseCode`.
  - `TouchqueAPIException::getCaseCode()` on refusals (blocked, frozen, rate limited, provisional, keys lost).
  - Steps (`start`, `Guard::run`, the relay and the Laravel middleware) carry `caseCode` and `reasons`; the guard
    keeps showing the code while it waits.

## [3.6.0] — 2026-10-19 — Never Locked Out

### Added
- **Never Locked Out.** A user whose phone is lost, dead or replaced moves to a new phone without a help desk:
  colleagues they named vouch on their own phones, then a cooling-off anyone can veto.
  - `$tq->recovery->setVouchers($user, $vouchers)` and `$tq->recovery->vouchers($user)` (who can vouch today and why
    not; new `Touchque\Resources\Recovery`). Ask for the user's phone before you change the list.
  - `$tq->recovery->start(['externalUsername' => ..., 'clientIp' => ..., 'displayName' => ..., 'fallbackVouchers' => [...],
    'required' => ..., 'coolOffMinutes' => ..., 'details' => [...]])` returns the recovery with `bindUri` (show it as a
    QR for the new phone); `status($id)`, `list(['externalUsername' => ...] | ['open' => true])`, `veto($id, $by, $reason)`,
    `Recovery::isOpen()`. Options are camelCase; an unknown key throws `TouchqueConfigException`.
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
- **Silent sign-ins.** Stop asking the phone again and again when nothing about a sign-in is new. Touchque's
  risk engine decides; the push is skipped only when it says so.
  - `$tq->risk->check(['externalUsername' => ..., 'type' => ..., 'clientIp' => ..., 'userAgent' => ..., 'browserProof' => ...,
    'maxAgeSeconds' => ...])` returns `['prompt', 'reasons', 'assurance', 'silentMode']` (new `Touchque\Resources\Risk`,
    options are camelCase; an unknown key throws `TouchqueConfigException`). Sends nothing to the phone. Read
    fail-closed: `prompt` is `false` only when the API answered the boolean `false`; malformed `reasons` become `[]`,
    a missing `assurance` is `normal` (`Risk::parseCheck()`).
  - `$tq->risk->browsers(['externalUsername' => ...])` and `$tq->risk->forgetBrowsers(['externalUsername' => ...,
    'thumbprint' => ...])`: the browsers Touchque knows for a user, and forgetting one or all of them.
  - `$browserProof` as the last argument of `$tq->login->request()`, `$tq->login->verify()`, `$tq->start()` and
    `Steps::start()`: the browser's device-bound key proof (`X-Touchque-Browser`, made by `@touchque/web` 1.4.0),
    passed through untouched; once the request is approved, Touchque knows that browser.
  - `silentSignIn` option (default off) on `TouchqueMiddleware` (constructor option or `protected $silentSignIn`),
    `RelayHandler` / `TouchqueRelay` (POST /login) and `Guard::run()` (new last arguments `$browserProof`,
    `$silentSignIn`): a new attempt carrying the `X-Touchque-Browser` header is checked first; `prompt: false`
    approves it at once with no push (`assurance.method` `silent`, `confirmedVia` `SILENT`, `requestId` `silent`,
    `reasons`; `onAuthenticated` gets `'via' => 'silent'`). Otherwise, and on any error in the check, the usual push
    starts with the proof attached. `['maxAgeSeconds' => int]` sets your own limit on the age of the last phone approval.
  - `Guard::BROWSER_HEADER` (`x-touchque-browser`), `Guard::silentInputFromHeaders()`.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), Touchque can move the request to a passkey, refuse it, or approve it as provisional.
  The approval array from `Steps::complete()` and `$tq->login->verify()` carry `provisional`, `revoked`, `revokeReason` and
  `reconfirmedAt`: a provisional approval lets the user in, but Touchque refuses their critical actions
  (`blocked` / `provisional`) until the phone re-confirms it after the call.
- `Webhook::REASON_*` and `Webhook::EVENT_*` constants for the webhook reasons (`vishing_suspected`, `phishing_origin`,
  `user_reported_coached`, and the existing ones) and events (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and
  the existing ones).
- **Mirror Alarm.** The first waiting step carries `$step['canary']`; `@touchque/web` 1.3.0 loads it on the page
  that shows the sign-in, so a real-time phishing proxy gets the approval refused (`phishing_origin`). Allow
  the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`$tq->login->verify()` throws `TouchquePasskeyRequiredError` (`$e->reason === 'step_up'`) when a poll shows the request now needs a passkey** (PENDING with
  `requiresPasskey`), instead of polling into a timeout. Finish it in the browser with `@touchque/web`. The
  error has a new `$reason` property (`policy` for the passkey-only policy, as before).
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code Touchque refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

## [3.3.0] — 2026-10-12

### Security
- **Adding a passkey needs the phone.** `RelayHandler`'s `/passkey/register/options` used to hand out
  registration options to anyone holding your app's session, and a passkey approves requests on its
  own, so a stolen session cookie could become a permanent second factor. For a user with a linked
  phone the route now answers the same two-phase step as `/login` (202 with the number to show; the
  user approves a `PASSKEY_ENROLL` request on the phone) and returns the options only after that
  approval, once. Users without a linked phone are unchanged. The Touchque API enforces this too:
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
  action, number-match code and details it showed, without trusting Touchque (same as the Node SDK's
  `verifyApprovalProof`). Fails closed without `expectedPublicKey` unless `allowUnpinnedKey` is true.
  Needs ext-openssl. Tested against `fixtures/approval-proof-vectors.json`, shared by all SDKs.
- **`$tq->login->reportFraud($requestId, $reason, $note)`** — report a request you later learned was
  fraud (chargeback, account takeover, social engineering). Touchque's risk engine uses it as its
  strongest training signal; the request's status does not change. Idempotent.
- **Relay routes (`Touchque\Relay\RelayHandler`)**, the PHP port of the Node SDK's `touchqueRouter`: the 14 routes
  `@touchque/web` calls (`POST /login`, enrollment, offline QR / codes, passkey sign-in, approval and management),
  framework-agnostic, returning a `RelayResponse`. Same security rules as Node: auth-required routes answer
  `401 UNAUTHORIZED_FOR_2FA` without a user; `getLoginUser` binds `/login` and the offline routes to the user who
  passed your first factor (`401 FIRST_FACTOR_REQUIRED`), and the offline routes are off
  (`403 OFFLINE_REQUIRES_FIRST_FACTOR`) until it or `allowOfflineWithoutFirstFactor` is set; `/enroll/start` never
  replaces a linked phone (`409 already_linked`); `/login` uses the guard's two-phase contract; sessions open only
  for the user Touchque returns; relay errors forward only Touchque's error code (`502 relay_error` for 5xx /
  network failures).
- **Built-in rate limiting** for the pre-auth routes (`FixedWindowLimiter`: 20 per IP and 5 per username per route
  per minute, `429 RATE_LIMITED` + `Retry-After`) with pluggable storage (`RateLimitStore`; the default
  `MemoryRateLimitStore` only helps in long-running workers, so use APCu/Redis under PHP-FPM).
- **Laravel adapter `Touchque\Laravel\TouchqueRelay`**: `TouchqueRelay::routes($router, 'touchque')` registers the
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
- New optional `ReplayCache $replayCache` argument (`Touchque\Webhook\ReplayCache`;
  implement it over Redis/APCu/DB — `MemoryReplayCache` only helps in
  long-running workers): a second delivery of the same `jti` throws
  `TouchqueWebhookReplayException` (a subclass of
  `TouchqueWebhookSignatureException`) — answer 200 to it, it is a duplicate.

## [2.0.0] — 2026-09-28

### Added
- `new Touchque()` with no arguments reads `TQ_API_KEY` / `TQ_API_SECRET` /
  `TQ_API_URL` from the environment.
- `$tq->start()` / `$tq->check()` / `$tq->complete()` — the headless step-up
  flow: start an approval, get back a JSON-safe "step" (the matching number,
  the enrollment QR, or a `blocked`/`frozen`/`rate_limited` refusal) to
  render in your own UI, and complete an approved request exactly once.
- `Touchque\Laravel\TouchqueMiddleware` (alias it as `touchque`) — one line
  per protected route, built on `Touchque\Guard::run()`. The matching number
  is now available **before** approval (previously only `Login::request()`'s
  raw response carried it, with no framework support for relaying it to the
  browser, so number matching could not be completed through a one-line guard).
- `$tq->offline` (`challenge`, `verify`, `verifyTotp`) and `$tq->actions`
  (`define`, `list`) — previously only in the Node SDK.
- `TouchqueAPIException::getStatus()` / `getErrorCode()` / `getReason()` /
  `getAttemptsLeft()` / `getRetryAfter()`; a network failure now throws
  `TouchqueNetworkException` instead of being indistinguishable from a real
  API error.
- `TouchquePasskeyRequiredError`, thrown by `Login::verify()` when a
  phishing-resistant policy requires a passkey.
- `WebAuthn::deleteCredential($id, $externalUsername = null)` — scope a
  deletion to one user (previously any credential id your key could reach
  was deletable).
- `Login::consume($requestId)` — uses an approved request exactly once.

### Changed
- **Breaking:** default `baseUrl` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, has no DNS record and
  was unreachable).
- **Breaking:** `Config` now throws `TouchqueConfigException` (not
  `\InvalidArgumentException`) for invalid/missing configuration.
- **Breaking:** `Login::verify()` now throws `TouchqueTimeoutException` (not
  `TouchqueRejectedException`) when a request expires unapproved, and
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
  Touchque Authenticator (2FA/MFA) product specifically. The PHP namespace
  is unchanged (`Touchque\`) — no code changes needed beyond the
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
- A PHP 8.5 deprecation warning in `TouchqueException::__construct()`
  (implicit nullable parameter).

## [1.0.0] — prior to this changelog

Initial public functionality: `Auth` (generateSecret/resetSecret),
`Login` (request/status/verify), `Webhook` (verify).
