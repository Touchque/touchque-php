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
routes and rules as the Node SDK's `touchqueRouter`. In Laravel, bind the
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
try {
    $event = $tq->webhook->verify($request->getContent(), $request->header('X-TouchQue-Signature'));
} catch (\TouchQue\Exceptions\TouchQueWebhookSignatureException $e) {
    return response('', 403); // not from TouchQue
}
```

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
