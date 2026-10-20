# touchque-authenticator/php-sdk

The official PHP server SDK for [TouchQue](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any backend with one
middleware line per route. Laravel adapter included.

[![Packagist](https://img.shields.io/packagist/v/touchque-authenticator/php-sdk.svg)](https://packagist.org/packages/touchque-authenticator/php-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[authenticator.touchque.com/docs](https://authenticator.touchque.com/docs)**

## Install

```bash
composer require touchque-authenticator/php-sdk
```

## Setup

Get an API key and secret from your [TouchQue Dashboard](https://authenticator.touchque.com):

```bash
TQ_API_KEY=tq_auth_your_key
TQ_API_SECRET=your_api_secret
```

`new TouchQue()` with no arguments reads these from the environment.

## Quick start (Laravel)

```php
// bootstrap/app.php (Laravel 11+)
$middleware->alias(['touchque' => \TouchQue\Laravel\TouchQueMiddleware::class]);

// a service provider
$this->app->singleton(\TouchQue\TouchQue::class, fn () => new \TouchQue\TouchQue());
```

```php
// routes/api.php
Route::post('/transfer', [TransferController::class, 'store'])
    ->middleware('touchque:SEND_MONEY');
```

Until the user approves on their phone, this answers
**`202 {"touchque": step, "token": "..."}`** instead of running your
controller. Your frontend renders `step` in its own UI (a matching number, or
a QR code the first time the user links the app) and sends the same request
again with header `X-TouchQue-Token: <token>` — see
[`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does
this loop for you in the browser. Once approved, the retried request reaches
your controller exactly once, with `$request->attributes->get('touchque')`
set to the approval.

The signed-in user comes from Laravel's own auth (`$request->user()`). For a
login route (no signed-in user yet), extend `TouchQueMiddleware` and override
`resolveUser()` to return whoever just passed your password step.

## Relay routes for `@touchque/web`

`RelayHandler` serves every route a frontend needs (`POST /login`, enrollment,
passkey ceremonies, offline codes) so you don't hand-write them — the same
routes and rules as the Node SDK's `touchqueRouter`. `POST
/passkey/authenticate/options` with no `email` answers options for any passkey
of your site, for `@touchque/web`'s passkey autofill. In Laravel, bind the
controller once and register the routes:

```php
// a service provider
use Illuminate\Http\Request;
use TouchQue\Laravel\TouchQueRelay;
use TouchQue\Relay\RelayResponse;

$this->app->singleton(TouchQueRelay::class, fn ($app) => new TouchQueRelay($app->make(\TouchQue\TouchQue::class), [
    // The user who already passed your password step. Binds POST /login and the
    // offline routes to them; the offline routes stay off (403) without it.
    'getLoginUser' => fn (Request $r) => $r->session()->get('password_verified_user'),
    'onAuthenticated' => function (Request $r, RelayResponse $res, array $info) {
        $r->session()->regenerate();
        $r->session()->put('user', $info['externalUsername']); // the user TouchQue approved
    },
    // 'rateLimit' => ['store' => new MyRedisRateLimitStore($redis)],  // see below
]));

// routes/web.php
TouchQueRelay::routes(app('router'), 'touchque');
```

The signed-in user for enrollment and passkey management defaults to
`$request->user()` (override with `'getUserId' => fn (Request $r) => ...`).
Pre-auth routes are rate limited per IP and per username (20 / 5 per minute per
route; `429 RATE_LIMITED` + `Retry-After`). The default counter store is in
memory, which under PHP-FPM starts empty on every request: give it a shared
store by implementing `TouchQue\Relay\RateLimitStore` over APCu or Redis, or
pass `'rateLimit' => false` and rate limit in front of the routes.

Without Laravel, build a `RelayHandler` with the same options plus a required
`getUserId`, and call
`$relay->handle($method, $pathAfterYourPrefix, $jsonBody, $clientIp, $userAgent, $headerGetter, $request)`;
it returns a `RelayResponse` (`getStatus()`, `getBody()`, `getHeaders()`,
`send()`), or `null` when no relay route matches.

## The three primitives, if you're not using Laravel

```php
use TouchQue\TouchQue;

$tq = new TouchQue(); // from TQ_API_KEY / TQ_API_SECRET

$step = $tq->start('SEND_MONEY', 'jane@acme.com', ['Amount' => '250 EUR', 'To' => 'DE89...']);
// $step['state']: 'waiting' (show $step['number']) | 'enroll' (show $step['enroll']['qrCodeDataUrl'])
//                 | 'approved' | 'rejected' | 'expired' | 'passkey_required' | 'frozen' | 'blocked'

$latest = $tq->check($step['requestId']);

// Once approved, consume it exactly once, right before doing the protected thing:
$approval = $tq->complete($step['requestId'], 'jane@acme.com', 'SEND_MONEY', ['Amount' => '250 EUR', 'To' => 'DE89...']);
```

`complete()` verifies the approval was actually issued for this user, action
and transaction, and can only be consumed once.

## Passkeys (phishing-resistant)

Push approval and offline codes stop password reuse and push fatigue, but a
real-time phishing proxy can still relay them. A passkey can't be phished —
the browser signs your site's real origin, and TouchQue refuses any other
(NIST SP 800-63B-4 §3.2.5). Register one via `$tq->webauthn` on the server and
`@touchque/web`'s `passkeys.register()` in the browser; optionally require it
for critical actions in the Dashboard's Security Policy.

## Offline sign

```php
$ch = $tq->offline->challenge('jane@acme.com', 'WITHDRAW', ['Amount' => '1,250.00 USD', 'Recipient' => 'Jane Doe']);
// show $ch['qrDataUrl'] — the phone scans it offline and shows a 7-character code
$result = $tq->offline->verify($ch['challengeId'], $code);
```

**A QR that follows a push.** Pass the push's request id when the offline QR is the fallback for a push the
user already started (the guard does this for you):

```php
$ch = $tq->offline->challenge('jane@acme.com', 'LOGIN', null, null, null, null, true, $step['requestId']);
// $ch['challengeCode'] is the number to print under the QR when number matching applies.
```

If the user **rejects the push on the phone, the offline QR dies with it**: no new QR is issued for that
sign-in (409 `request_rejected`), a code for a QR already on screen is refused (`reason` = `request_rejected`)
and so is the time-based code (`verifyTotp(..., $requestId)`). With number matching, print `challengeCode` under
the QR: the phone shows it among two decoys and the user taps the match; a wrong tap yields a code that fails
verification.

## Webhooks

```php
use TouchQue\Resources\Webhook;

try {
    $event = $tq->webhook->verify($request->getContent(), $request->header('X-Signature'));
} catch (\TouchQue\Exceptions\TouchQueWebhookSignatureException $e) {
    return response('', 403); // not from TouchQue
}
if (($event['event'] ?? null) === Webhook::EVENT_APPROVAL_REVOKED) {
    endSessionsBuiltOn($event['requestId']);
}
```

Login results carry `status` (`SUCCESS` | `REJECTED`) and, when rejected, a `reason` (`TouchQue\Resources\Webhook::REASON_*`):
`user_rejected`, `user_reported_fraud`, `user_reported_coached` (the user said someone on the phone told
them to approve), `risk_reversed`, `risk_step_up`, `approval_signature_invalid`, `device_integrity_failed`,
`vishing_suspected` and `phishing_origin` (see Vishing Shield). Treat a reason you do not know as a rejection.
Event webhooks carry `event` (`TouchQue\Resources\Webhook::EVENT_*`): `DEVICE_LINKED`, `DEVICE_UNLINKED`, `PASSKEY_REGISTERED`,
`PASSKEY_DELETED`, `APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`. Ignore events you do not know.

## Vishing Shield (someone on the phone guiding the user)

The phone tells TouchQue, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow and the relay handle it; the blocking `$tq->login->verify()` throws
  `TouchQuePasskeyRequiredError` (`$e->reason === 'step_up'`). No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: vishing_suspected`).
- **Provisional.** Anything else is approved with `provisional` set on the approval array from `Steps::complete`. Let the user
  in, but treat the session as limited: TouchQue refuses the user's critical actions (`blocked` / `provisional`)
  until the phone re-confirms after the call (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason` `COACHED` or
  `UNDO`) means end the session; an approval revoked before you consumed it can no longer be consumed
  (409 `revoked`).

**Mirror Alarm.** The first waiting step carries `canary.url`. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: phishing_origin`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## TouchQue Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [ACTIONS.md](../ACTIONS.md).

```php
$tq->actions->deploy('night-alert', ['trigger' => 'approval.decided',
    'template' => ['id' => 'alert', 'params' => ['channel' => 'slack', 'when' => ['countries' => ['TR'], 'hours' => ['from' => 0, 'to' => 6]]]]]);

$draft = 'exports.onExecute = async (event, api) => { if (event.context?.amount > 10000) api.stepUp("Over 10,000"); };';
$report = $tq->actions->dryRun(['trigger' => 'login.request', 'code' => $draft]); // $report['transitions']
$tq->actions->deploy('big-transfers', ['trigger' => 'login.request', 'code' => $draft]);
```

Give Actions what only your server knows with the middleware's `context` option
(`['context' => fn ($request) => ['roles' => $request->user()->roles]]`), never
shown on the phone. Loosening calls need a capability an admin approves on their
phone. Action types moved to `$tq->actionTypes` in 4.0.

## Silent sign-ins (stop asking when nothing is new)

A user who approved on their phone in this browser a little while ago, from the same phone, network and country,
with no risk signal since, does not need another push. TouchQue's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 1.4.0 with `createTouchQueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-TouchQue-Browser` header.
2. On the server, turn on `silentSignIn`:

```php
// a service provider
use Illuminate\Http\Request;
use TouchQue\Laravel\TouchQueMiddleware;
use TouchQue\Laravel\TouchQueRelay;
use TouchQue\Relay\RelayResponse;

// The relay's POST /login
$this->app->singleton(TouchQueRelay::class, fn ($app) => new TouchQueRelay($app->make(\TouchQue\TouchQue::class), [
    'getLoginUser' => fn (Request $r) => $r->session()->get('password_verified_user'),
    'onAuthenticated' => function (Request $r, RelayResponse $res, array $info) {
        // $info['via'] is 'silent' when no push was needed
        $r->session()->regenerate();
        $r->session()->put('user', $info['externalUsername']);
    },
    'silentSignIn' => true, // or ['maxAgeSeconds' => 8 * 3600] for your own limit
]));

// The middleware: when binding it, or in your subclass (protected $silentSignIn = true;)
$this->app->bind(TouchQueMiddleware::class, fn ($app) => new TouchQueMiddleware(
    $app->make(\TouchQue\TouchQue::class),
    ['silentSignIn' => true]
));
```

With it on, a new attempt that carries the header first calls `$tq->risk->check()`. Only an answer of exactly
`prompt: false` approves it at once, with nothing sent to the phone: the approval (`$request->attributes->get('touchque')`)
has `assurance` `['method' => 'silent', 'phishingResistant' => false]`, `confirmedVia` `SILENT`, `requestId` `silent`
and `reasons` (`known_browser`, `recent_approval`, `same_phone`, `familiar_network`, `no_risk_signal`); the relay
calls `onAuthenticated` with `'via' => 'silent'`. Anything else, and any error in the check, starts the usual push
with the proof attached, so its approval makes the browser known. Polling with the token never checks again.
`Guard::run()` takes the same option (its last two arguments: `$browserProof`, `$silentSignIn`).

TouchQue only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
on the phone (a confirmed push, not one approved during a call, or a passkey) within your `maxAgeSeconds` and at most
7 days ago, by the phone that is linked now; the country and the network were seen in the user's earlier approved
sign-ins; the risk engine allows it with no risk signal; and the action is an everyday one. A critical action always
asks. In `shadow` mode (`silentMode`) it always asks and the reasons say what would have happened.

Without the adapters (options are arrays with camelCase keys):

```php
$browserProof = $request->header('X-TouchQue-Browser');
$risk = $tq->risk->check([
    'externalUsername' => $user, 'type' => 'LOGIN', 'clientIp' => $request->ip(), 'browserProof' => $browserProof,
]);
if ($risk['prompt'] === false) {
    return openSession($user); // $risk['reasons'] say why
}
$step = $tq->start('LOGIN', $user, null, null, $request->ip(), $request->userAgent(), $browserProof); // the approval makes the browser known

$browsers = $tq->risk->browsers(['externalUsername' => $user])['browsers'];   // for an "approved browsers" list
$tq->risk->forgetBrowsers(['externalUsername' => $user]);                     // all; add 'thumbprint' for one
```

`$tq->login->request()` takes the proof as its last argument (`$browserProof`) too. Forget a user's browsers after a
password reset or a "sign out everywhere". `check()` reads the answer fail-closed: `prompt` is `false` only when
TouchQue answered the boolean `false`.

## Never Locked Out (lost, dead or new phone)

A user whose phone is gone moves to a new phone without a help desk. Colleagues they named beforehand vouch on their own
phones, each typing a number the user reads them on a call; then a cooling-off (default 60 minutes) lets the old phone, any
voucher or an admin stop it. The risk engine can refuse it or ask for more vouchers, and for 24 hours afterwards critical
actions are refused. It is an option: offer it next to passkeys and the old phone's transfer, never as the only way. Every
step is a hash-chained receipt (`receipts`); a voucher's step carries the signature of their phone's hardware key.

```php
// Settings page, after an approval on the user's phone:
$tq->recovery->setVouchers($user, ['bo@acme.com', 'cy@acme.com']);

// "I lost my phone", after the password:
$r = $tq->recovery->start(['externalUsername' => $user, 'clientIp' => $ip, 'displayName' => 'Ada', 'fallbackVouchers' => $admins]);
showQr($r['bindUri']);                       // the TouchQue app on the new phone scans it
$now = $tq->recovery->status($r['recoveryId']); // each voucher's 'code' to read to them
// $now['status']: AWAITING_DEVICE -> VOUCHING -> COOLING -> COMPLETED (or VETOED / EXPIRED / FAILED)

$tq->recovery->veto($r['recoveryId'], 'admin@acme.com'); // an admin who does not believe it
```

## "Why?": case codes instead of guesswork

Every approval decision names a short case code (`K7P-2QX`: 6 characters, no I, O, 0 or 1). A user who was asked to
match a number, needed a passkey or was refused reads it out to your support team, and the team opens the whole
decision by it in the TouchQue dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
that matched, the risk signals that were acted on and the ones only measured), and the single change that would have
let it through. No screenshots, no log digging. The code opens nothing on its own: only your workspace sees its
decisions.

```php
$step = $client->start('WITHDRAW', $user);
// $step['caseCode'] → 'K7P-2QX'; $step['reasons'] → [['code' => 'critical_action', 'text' => 'The action is marked critical']]
try {
    $client->login->request($user, 'LOGIN');
} catch (TouchQueAPIException $e) {
    if ($e->getCaseCode() !== null) {
        show('Tell your support team: ' . $e->getCaseCode());
    }
}
```

`caseCode` is in the `login->request` and `risk->check` answers and every step (the guard keeps it while it waits);
`TouchQueAPIException::getCaseCode()` carries it on refusals.

## Blocking `verify()` and number matching

`$tq->login->verify()` sends the request and waits for the phone in one call. With number matching (your option, a
workspace policy, a critical action or the risk engine can turn it on) the phone asks the user to pick a number,
and the call returns only after they have. Pass `$onChallenge` (the 11th argument; PHP 8: `onChallenge:`): it runs
once, right after the request is created and before the wait. **Show `challengeCode` to the user now; the phone
asks for it.**

```php
$tq->login->verify($user, 'SEND_MONEY', null, 30000, $ip, $userAgent, false, false, null, null,
    function (array $c) {
        if (isset($c['challengeCode'])) {
            notifyUser("Pick {$c['challengeCode']} on your phone", $c['caseCode'] ?? null);
        }
    });
```

It gets an array with `requestId`, `expiresAt` and, when present, `challengeCode`, `reasons` and `caseCode`. It is
not called when only a passkey can approve (`verify()` throws `TouchQuePasskeyRequiredError` first). Anything it
throws is logged with `error_log` and ignored: `verify()` keeps waiting. In a web request, where the page hears
nothing until you answer, use the relay or `$tq->start()`: their first answer already carries the number.

## Verifying the device proof (no need to trust TouchQue)

Every approval from a phone with a hardware key carries `approvalProof`: the phone's own
signature over the request id, action, number-match code and the exact details it showed.

```php
use TouchQue\ApprovalProof;

$ok = ApprovalProof::verify($event['approvalProof'] ?? null, [
    'requestId' => $requestId, 'type' => 'WITHDRAW', 'details' => $details,
    'challengeCode' => $challengeCode,
    'expectedPublicKey' => $user->touchque_device_key, // stored from their first verified approval
]);
```

Without `expectedPublicKey` it returns `false` unless `allowUnpinnedKey` is `true` (trust on first
use — store `$proof['publicKey']`, then pin it).

## Reporting fraud

Learned later that an approved request was fraud? Report it — it is the strongest signal
TouchQue's risk engine learns from, and it stays in your audit log:

```php
$tq->login->reportFraud($requestId, 'chargeback', 'Disputed by card holder');
// reason: 'chargeback' | 'account_takeover' | 'social_engineering' | 'other'
```

## Errors

All SDK exceptions extend `TouchQueException`: `TouchQueAPIException`,
`TouchQueNetworkException`, `TouchQueConfigException`,
`TouchQuePasskeyRequiredError`.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-TouchQue-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Requirements

- PHP 8.1+
- A [TouchQue Dashboard](https://authenticator.touchque.com) account
- Laravel 10+ for the bundled middleware (optional)

## License

MIT © [TouchQue](https://touchque.com)
