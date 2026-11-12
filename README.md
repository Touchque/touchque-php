# touchque-authenticator/php-sdk

The official PHP server SDK for [Touchque](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any backend with one
middleware line per route. Laravel adapter included.

[![Packagist](https://img.shields.io/packagist/v/touchque-authenticator/php-sdk.svg)](https://packagist.org/packages/touchque-authenticator/php-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
composer require touchque-authenticator/php-sdk
```

## Setup

Get an API key and secret from your [Touchque Dashboard](https://dashboard.touchque.com):

```bash
TQ_API_KEY=tq_auth_your_key
TQ_API_SECRET=your_api_secret
```

`new Touchque()` with no arguments reads these from the environment.

## Quick start (Laravel)

```php
// bootstrap/app.php (Laravel 11+)
$middleware->alias(['touchque' => \Touchque\Laravel\TouchqueMiddleware::class]);

// a service provider (optional: for your own Config, a logger or a base URL)
$this->app->singleton(\Touchque\Touchque::class, fn () => new \Touchque\Touchque());
```

The middleware takes the client from Laravel's container on the first request: your binding, or
one built from `TQ_API_KEY` / `TQ_API_SECRET`.

```php
// routes/api.php
Route::post('/transfer', [TransferController::class, 'store'])
    ->middleware('touchque:SEND_MONEY');
```

Until the user approves on their phone, this answers
**`202 {"touchque": step, "token": "..."}`** instead of running your
controller. Your frontend renders `step` in its own UI (a matching number, or
a QR code the first time the user links the app) and sends the same request
again with header `X-Touchque-Token: <token>` — see
[`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does
this loop for you in the browser. Once approved, the retried request reaches
your controller exactly once, with `$request->attributes->get('touchque')`
set to the approval.

A frontend of your own: while the first-time QR is up, polls answer `{"state": "enroll", "expiresAt": ...}`
without `enroll`, so keep showing the QR you have; a new one comes with `enroll.qrCodeDataUrl`.

The signed-in user comes from Laravel's own auth (`$request->user()`). For a
login route (no signed-in user yet), extend `TouchqueMiddleware` and override
`resolveUser()` to return whoever just passed your password step.

**A missing key.** Without `TQ_API_KEY` / `TQ_API_SECRET` nothing throws, at boot or on a request.
A guarded route answers **500** with `Cache-Control: no-store` and the body
`{"touchque":{"state":"blocked","reason":"misconfigured"},"error":{"code":"misconfigured","message":"Two-factor approval is not configured correctly."}}`
(401 `unauthenticated` when nobody is signed in), and your controller never runs. The middleware
logs it once, through Laravel's logger: `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes
guarded by Touchque answer 500 misconfigured.` A 500 rather than a 503: it is a deploy mistake for your
monitoring to catch, not an outage to retry. `@touchque/web` shows "Approvals are not set up correctly
on this site."

**Refusal headers.** Every answer of 400 and above carries `X-Touchque-State: <state>`, plus
`X-Touchque-Reason: <reason>` when the step has one; `@touchque/web` 2.1.0 reads the step from them when
the body has no `touchque` key. A frontend on another origin must list them in
`Access-Control-Expose-Headers`.

### Your own error shape (`errorBody`)

Refusals (403, 408, 423, 429) answer `{"touchque": step, "token": "..."}`; the guard's own errors (401,
500, 503) answer `{"touchque": step, "error": {"code", "message"}}`. To answer in your API's own error
shape, give the middleware an `errorBody` callable when you bind it (or set `$this->errorBody` in your
subclass's constructor):

```php
// a service provider
use Touchque\Laravel\TouchqueMiddleware;

$this->app->bind(TouchqueMiddleware::class, fn () => new TouchqueMiddleware(null, [
    'errorBody' => fn (array $r) => ['message' => $r['message'], 'code' => $r['code']],
]));
```

It is called for every answer of 400 and above (401, 403, 408, 423, 429, 500, 503), never for a 202
step or an approval, with the refusal:

- `status`;
- `code`: the error's code, else the step's `reason`, else its `state`;
- `message`: the error's message, else by state: "The approval was rejected.", "The approval expired.
  Try again.", "Too many rejected approvals. Try again later." (`frozen`), "Too many attempts. Try again
  later." (`rate_limited`), "The approval was refused." (anything else);
- `touchque`: the step as it would be sent.

What the result encodes to, the way `JsonResponse` encodes it, decides. A JSON object (an array with
string keys, an object, a `JsonSerializable`, an `Arrayable` or `Jsonable` such as a Collection) is sent
with `touchque` set to the step, replacing yours, so `@touchque/web` still sees the state: 403
`{"message":"The approval was rejected.","code":"rejected","touchque":{"state":"rejected",...}}`. No
`token` is added. Anything else (a string, a number, a list, `null`) is sent as it is. The callable gets a
copy of the step. The status and the headers stay the same (JSON, `Cache-Control: no-store`,
`Retry-After`, `X-Touchque-State`). A callable that throws, or a result that cannot be encoded, is logged
(`[Touchque] errorBody failed: <message>`) and the default body is sent.

## Action types

`'SEND_MONEY'` above is an action type: one kind of approval, with the title the phone shows and
whether it is critical. Define each one once, in the dashboard (**Developers → Action types**)
or from code:

```php
$tq->actionTypes->define('SEND_MONEY', 'Send money', null, true);   // type, name, description, critical
```

The guard refuses what is not ready. A name that is not defined is a setup error
(`TouchqueConfigException`, "Unknown action …"): the guard answers 500 with `reason: 'misconfigured'`. A type
turned off in the dashboard answers 403 with `reason: 'action_disabled'`, which stops that kind of
approval at once, without a deploy.

## Guard inside your handler

When your own checks come first (the balance, who owns the account), run the guard in your handler,
after them, with `Guard::run()`: the middleware's two-phase contract, for Laravel or any framework.

```php
use Touchque\Guard;

// Your checks first, on every request (each poll comes back through them).
if ($account->ownerEmail !== $user || $account->balance < $amount) {
    return json(['error' => 'not_allowed'], 403);
}

$in = Guard::inputFromHeaders(fn (string $name) => $request->header($name)); // any case-insensitive getter
$result = Guard::run(
    $tq, $user, 'SEND_MONEY',
    ['Amount' => "$amount EUR", 'To' => $account->iban], // shown on the phone, bound to the approval
    null, $clientIp, $userAgent,
    $in['token'], $in['offline'], $in['code'], $in['codeType']
);

if (isset($result['approved'])) {
    $transfers->send($account, $amount); // approved: runs once
    return json(['sent' => true], 200);
}

// Cache-Control: no-store, Retry-After on 423 / 429, X-Touchque-State (and -Reason) on 400 and above
return json($result['body'], $result['status'], Guard::headers($result)); // your framework's JSON response
```

- **202** `{"touchque": step, "token": "..."}`: show the step and send the same request again with
  `X-Touchque-Token: <token>` until it is approved (`@touchque/web` does this loop).
- **200** with `$result['approved']`: run the action once. The approval is used up there: the same
  token never approves twice.
- **401, 403, 408, 423, 429, 500, 503**: send `status` and `body` as they are, with
  `Guard::headers($result)`: `Cache-Control: no-store`, `Retry-After` on 423 and 429, `X-Touchque-State`
  and `X-Touchque-Reason`. For your own error shape, `Guard::errorBody($result, $errorBody)` judges
  `json_encode()` of what your callable returns, as it is (it does not convert Laravel's `Arrayable` /
  `Jsonable` as the middleware does): a JSON object gets `touchque`. It throws when your callable
  throws or the result cannot be encoded. Encode `null` yourself (Laravel's `JsonResponse(null)` sends `{}`).
- **First-time QR**: a user with no phone linked gets the step `enroll` with `enroll.qrCodeDataUrl`, the
  recovery codes and `enroll.expiresAt`. While the first-time QR is up, polls answer
  `{state: "enroll", expiresAt}` without `enroll`: keep showing the QR you have. A new QR comes with
  `enroll.qrCodeDataUrl` when the old one expired. Pages on `@touchque/web` need 2.1.0.
- **Rate limits**: `Guard::isStatusPoll()` tells a poll from a new attempt (a poll only reads the status).
  If you count attempts per user, pass `Guard::run()` a last argument `$beforeStart`: a callable it calls
  when a first-time QR poll starts after all (the user linked, or the QR expired), to charge that start;
  return a result to answer instead, or null to go on (anything else throws). The relay does this for
  `POST /login`.

`Guard::run()` needs a client: `new Touchque()` throws `TouchqueConfigException` when a key is missing,
so build it where you handle that (the Laravel middleware answers 500 `misconfigured` for you).

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
use Touchque\Laravel\TouchqueRelay;
use Touchque\Relay\RelayResponse;

$this->app->singleton(TouchqueRelay::class, fn ($app) => new TouchqueRelay($app->make(\Touchque\Touchque::class), [
    // The user who already passed your password step. Binds POST /login and the
    // offline routes to them; the offline routes stay off (403) without it.
    'getLoginUser' => fn (Request $r) => $r->session()->get('password_verified_user'),
    'onAuthenticated' => function (Request $r, RelayResponse $res, array $info) {
        $r->session()->regenerate();
        $r->session()->put('user', $info['externalUsername']); // the user Touchque approved
    },
    // 'rateLimit' => ['store' => new MyRedisRateLimitStore($redis)],  // see below
]));

// routes/web.php
TouchqueRelay::routes(app('router'), 'touchque');
```

The signed-in user for enrollment and passkey management defaults to
`$request->user()` (override with `'getUserId' => fn (Request $r) => ...`).
Pre-auth routes are rate limited per IP and per username (20 / 5 per minute per
route; `429 RATE_LIMITED` + `Retry-After`). Polls of an approval on its way have
their own per-IP budget; a first-time QR poll that starts after all (the user
linked, or the QR expired) counts against the username's budget like a new
attempt. Guard answers of 400 and above carry `X-Touchque-State` (and
`X-Touchque-Reason`). The default counter store is in
memory, which under PHP-FPM starts empty on every request: give it a shared
store by implementing `Touchque\Relay\RateLimitStore` over APCu or Redis, or
pass `'rateLimit' => false` and rate limit in front of the routes.

Without Laravel, build a `RelayHandler` with the same options plus a required
`getUserId`, and call
`$relay->handle($method, $pathAfterYourPrefix, $jsonBody, $clientIp, $userAgent, $headerGetter, $request)`;
it returns a `RelayResponse` (`getStatus()`, `getBody()`, `getHeaders()`,
`send()`), or `null` when no relay route matches.

## The three primitives, if you're not using Laravel

```php
use Touchque\Touchque;

$tq = new Touchque(); // from TQ_API_KEY / TQ_API_SECRET

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
the browser signs your site's real origin, and Touchque refuses any other
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
use Touchque\Resources\Webhook;

try {
    $event = $tq->webhook->verify($request->getContent(), $request->header('X-Signature'));
} catch (\Touchque\Exceptions\TouchqueWebhookSignatureException $e) {
    return response('', 403); // not from Touchque
}
if (($event['event'] ?? null) === Webhook::EVENT_APPROVAL_REVOKED) {
    endSessionsBuiltOn($event['requestId']);
}
```

Login results carry `status` (`SUCCESS` | `REJECTED`) and, when rejected, a `reason` (`Touchque\Resources\Webhook::REASON_*`):
`user_rejected`, `user_reported_fraud`, `user_reported_coached` (the user said someone on the phone told
them to approve), `risk_reversed`, `risk_step_up`, `approval_signature_invalid`, `device_integrity_failed`,
`vishing_suspected` and `phishing_origin` (see Vishing Shield). Treat a reason you do not know as a rejection.
Event webhooks carry `event` (`Touchque\Resources\Webhook::EVENT_*`): `DEVICE_LINKED`, `DEVICE_UNLINKED`, `PASSKEY_REGISTERED`,
`PASSKEY_DELETED`, `APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, `MOBILE_PUSH` (Mobile SDK), `RECOVERY_*` (Never Locked Out:
`STARTED`, `DEVICE_BOUND`, `COOLING`, `COMPLETED`, `VETOED`, `EXPIRED`, `FAILED`) and `ASSIST_*` (help desk: `OPENED`, `ENDED`,
`CHECK_PASSED`, `CHECK_FAILED`, `UNFROZEN`, `CLAIM_CONFIRMED`, `CLAIM_UNVERIFIED`). Ignore events you do not know.

## Shared Signals (security events from Touchque SSO)

After sign-in, Touchque SSO tells your app when something happens to an organization member's account: sessions
revoked, a credential changed or compromised, the account disabled, a device out of compliance. It sends Security
Event Tokens (OpenID Shared Signals Framework 1.0, CAEP and RISC) to the receivers the organization's admin adds
(Organization > Continuous access). `SecurityEventVerifier` checks each one: the RS256 signature with the issuer's
keys (found from its `/.well-known/ssf-configuration`, https only), `typ`, issuer, audience and exactly one event.

Push delivery (RFC 8935): the SET is the request body (`application/secevent+jwt`).

```php
use Touchque\SecurityEventVerifier;
use Touchque\Exceptions\TouchqueSecurityEventException;

$verifier = new SecurityEventVerifier(['issuer' => 'https://sso.touchque.com', 'audience' => 'https://app.example.com']);
try {
    $event = $verifier->verify(file_get_contents('php://input'));
} catch (TouchqueSecurityEventException $e) {
    // temporarily_unavailable: the keys could not be read; 503 makes the transmitter try again.
    http_response_code($e->error === 'temporarily_unavailable' ? 503 : 400);
    echo json_encode(['err' => $e->error, 'description' => $e->getMessage()]);
    exit;
}
if (in_array($event['name'], ['session-revoked', 'account-disabled'], true)) {
    endSessionsOf($event['subject']['email'] ?? null);
}
http_response_code(202);
```

Poll delivery (RFC 8936), with the stream's token: the next poll acknowledges what you handled.

```php
$ack = [];
do {
    $page = SecurityEventVerifier::poll($pollUrl, $streamToken, ['ack' => $ack, 'returnImmediately' => true]);
    $ack = [];
    foreach ($page['sets'] as $jti => $set) {
        handle($verifier->verify($set));
        $ack[] = $jti;
    }
} while ($page['moreAvailable'] || $ack);
```

`$event` has `jti`, `issuer`, `audience`, `issuedAt`, `txn` (the case code of Touchque's decision), `subject`
(`['format' => 'email', 'email' => ...]` for a person), `type`, `name` (`session-revoked`, `credential-change`,
`device-compliance-change`, `account-disabled`, `credential-compromise`; `SecurityEventVerifier::TYPES`) and
`claims`. A SET does not expire: keep the jtis you handled and skip a repeat. A SET you could not handle goes back
in `setErrs` (`[$jti => ['err' => ..., 'description' => ...]]`) instead of `ack`.

## Vishing Shield (someone on the phone guiding the user)

The phone tells Touchque, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow and the relay handle it; the blocking `$tq->login->verify()` throws
  `TouchquePasskeyRequiredError` (`$e->reason === 'step_up'`). No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: vishing_suspected`).
- **Provisional.** Anything else is approved with `provisional` set on the approval array from `Steps::complete`. Let the user
  in, but treat the session as limited: Touchque refuses the user's critical actions (`blocked` / `provisional`)
  until the phone re-confirms after the call (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason` `COACHED` or
  `UNDO`) means end the session; an approval revoked before you consumed it can no longer be consumed
  (409 `revoked`).

**Mirror Alarm.** The first waiting step carries `canary.url`. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: phishing_origin`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## Touchque Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [support.touchque.com/actions](https://support.touchque.com/actions).

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

## AI agents (an identity per agent, never your API key)

Register each agent with its **public** key; the private key stays where the agent runs. The agent signs in
with its own key and gets a 10-minute token bound to that key (DPoP).

```php
use Touchque\AgentKeys;
use Touchque\TouchqueAgent;

$keys = AgentKeys::generate();                        // or where the agent runs
$agent = $tq->agents->create('Invoice bot', ['PAY_INVOICE'], [
    'publicKey' => $keys['publicJwk'],
    'ownerEmail' => 'ada@acme.com',                   // accountable; the agent stops if they leave
]);
// store $agent['id'] and $keys['privateJwk'] in the agent's secrets (TQ_AGENT_ID, TQ_AGENT_KEY)

$me = (new TouchqueAgent())->me();                    // in the agent
```

`$tq->agents->suspend($id)` stops one agent at once, `$tq->agents->setKillSwitch(true)` every agent.

```php
$ask = $agent->requestApproval('jane@example.com', 'PAY_INVOICE', [[
    'type' => 'payment_initiation', 'instructedAmount' => ['currency' => 'TRY', 'amount' => '500.00'],
    'creditorName' => 'Jane Doe', 'creditorAccount' => ['iban' => 'TR330006100519786457841326'],
]], ['reason' => 'October rent']);
$token = $agent->waitForApproval($ask['approvalId'])['approvalToken'];

// in your executor, right before paying: used once, only for what you are about to do
$approval = $tq->agents->redeemApproval($token, ['user' => 'jane@example.com', 'type' => 'PAY_INVOICE',
    'authorizationDetails' => ['type' => 'payment_initiation', 'instructedAmount' => ['currency' => 'TRY', 'amount' => '500.00']]]);
```


### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (Touchque SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

```php
use Touchque\AgentCard;
use Touchque\CrossAppAccess;
use Touchque\IdJagVerifier;

$jag = CrossAppAccess::requestIdJag(['issuer' => 'https://sso.touchque.com', 'clientId' => $clientId, 'clientSecret' => $secret,
    'idToken' => $idToken, 'audience' => 'https://auth.files.example']);
$tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => 'https://auth.files.example/token', 'clientId' => 'acme',
    'clientSecret' => $filesSecret, 'assertion' => $jag['assertion']]);

// Your own authorization server (jwt-bearer grant):
$claims = (new IdJagVerifier(['issuer' => 'https://sso.touchque.com', 'audience' => 'https://auth.files.example']))
    ->verify($_POST['assertion'], $authenticatedClientId);

AgentCard::verify($cardJson, ['cardUrl' => 'https://agent.example/.well-known/agent-card.json']);
```

## Silent sign-ins (stop asking when nothing is new)

A user who approved on their phone in this browser a little while ago, from the same phone, network and country,
with no risk signal since, does not need another push. Touchque's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 2.0.0 with `createTouchqueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-Touchque-Browser` header.
2. On the server, turn on `silentSignIn`:

```php
// a service provider
use Illuminate\Http\Request;
use Touchque\Laravel\TouchqueMiddleware;
use Touchque\Laravel\TouchqueRelay;
use Touchque\Relay\RelayResponse;

// The relay's POST /login
$this->app->singleton(TouchqueRelay::class, fn ($app) => new TouchqueRelay($app->make(\Touchque\Touchque::class), [
    'getLoginUser' => fn (Request $r) => $r->session()->get('password_verified_user'),
    'onAuthenticated' => function (Request $r, RelayResponse $res, array $info) {
        // $info['via'] is 'silent' when no push was needed
        $r->session()->regenerate();
        $r->session()->put('user', $info['externalUsername']);
    },
    'silentSignIn' => true, // or ['maxAgeSeconds' => 8 * 3600] for your own limit
]));

// The middleware: when binding it, or in your subclass (protected $silentSignIn = true;)
$this->app->bind(TouchqueMiddleware::class, fn () => new TouchqueMiddleware(
    null, // the client: from the container on the first request
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

Touchque only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
on the phone (a confirmed push, not one approved during a call, or a passkey) within your `maxAgeSeconds` and at most
7 days ago, by the phone that is linked now; the country and the network were seen in the user's earlier approved
sign-ins; the risk engine allows it with no risk signal; and the action is an everyday one. A critical action always
asks. In `shadow` mode (`silentMode`) it always asks and the reasons say what would have happened.

Without the adapters (options are arrays with camelCase keys):

```php
$browserProof = $request->header('X-Touchque-Browser');
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
Touchque answered the boolean `false`.

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
showQr($r['bindUri']);                       // the Touchque app on the new phone scans it
$now = $tq->recovery->status($r['recoveryId']); // each voucher's 'code' to read to them
// $now['status']: AWAITING_DEVICE -> VOUCHING -> COOLING -> COMPLETED (or VETOED / EXPIRED / FAILED)

$tq->recovery->veto($r['recoveryId'], 'admin@acme.com'); // an admin who does not believe it
```

## "Why?": case codes instead of guesswork

Every approval decision names a short case code (`K7P-2QX`: 6 characters, no I, O, 0 or 1). A user who was asked to
match a number, needed a passkey or was refused reads it out to your support team, and the team opens the whole
decision by it in the Touchque dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
that matched, the risk signals that were acted on and the ones only measured), and the single change that would have
let it through. No screenshots, no log digging. The code opens nothing on its own: only your workspace sees its
decisions.

```php
$step = $client->start('WITHDRAW', $user);
// $step['caseCode'] → 'K7P-2QX'; $step['reasons'] → [['code' => 'critical_action', 'text' => 'The action is marked critical']]
try {
    $client->login->request($user, 'LOGIN');
} catch (TouchqueAPIException $e) {
    if ($e->getCaseCode() !== null) {
        show('Tell your support team: ' . $e->getCaseCode());
    }
}
```

`caseCode` is in the `login->request` and `risk->check` answers and every step (the guard keeps it while it waits);
`TouchqueAPIException::getCaseCode()` carries it on refusals.

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
not called when only a passkey can approve (`verify()` throws `TouchquePasskeyRequiredError` first). Anything it
throws is logged with `error_log` and ignored: `verify()` keeps waiting. In a web request, where the page hears
nothing until you answer, use the relay or `$tq->start()`: their first answer already carries the number.

Sent the request yourself with `$tq->login->request()`? `$tq->login->waitForApproval($requestId, $timeoutMs = 30000,
$pollIntervalMs = 400)` is the waiting half of `verify()`: the same answer (`approved`, `status`, `requestId`,
`assurance`, `confirmedVia`, `provisional`), and it throws what `verify()` throws while it waits.

## Verifying the device proof (no need to trust Touchque)

Every approval from a phone with a hardware key carries `approvalProof`: the phone's own
signature over the request id, action, number-match code and the exact details it showed.

```php
use Touchque\ApprovalProof;

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
Touchque's risk engine learns from, and it stays in your audit log:

```php
$tq->login->reportFraud($requestId, 'chargeback', 'Disputed by card holder');
// reason: 'chargeback' | 'account_takeover' | 'social_engineering' | 'other'
```

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the Touchque app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (Touchque keeps its hash).

```php
$p = $tq->qrPairings->create($keyThumbprint, ['clientIp' => $request->ip(), 'userAgent' => $request->userAgent()]);
// show $p['uri'] (touchque://pair-browser?...) as a QR code; poll:
$now = $tq->qrPairings->get($p['pairingId']);       // waiting -> scanned -> confirmed
if ($now['state'] === 'confirmed') {
    // the 17th argument (PHP 8: qrPairing: $p['pairingId'])
    $tq->login->request($now['externalUsername'], 'LOGIN', null, null, null, false, false, null, null, null, null, null, null, null, null, null, $p['pairingId']);
}
// or: $tq->qrPairings->refuse($p['pairingId'], 'device_not_approved', 'Ask IT to approve this computer.');
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: Touchque only ever holds the ciphertext. Such a request lives 5 minutes.

```php
$key = \Touchque\CodeReply::newKey();   // keep $key['privateKey'] for this request
$sent = $tq->login->request($user, reply: ['kind' => 'code', 'key' => $key['publicKey'], 'channel' => 'sms', 'target' => '+**********26']);
$status = $tq->login->status($sent['requestId']);   // once CONFIRMED
$code = isset($status['reply']) ? \Touchque\CodeReply::open($key['privateKey'], $sent['requestId'], $status['reply']['ct']) : null;
```

## Safe Guard (Safe transactions approved on the phone)

TouchqueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```php
use Touchque\SafeApproval;

$target = ['chainId' => 1, 'safe' => $safe, 'guard' => $guard, 'tx' => ['to' => $to, 'value' => '0', 'data' => $data, 'operation' => 0, 'nonce' => 42]];
$sent = $tq->safeGuard->request('treasurer@acme.com', 'safe_payment', $target + [   // an action type from your dashboard
    'config' => ['threshold' => 2, 'govThreshold' => 3, 'govDelay' => 172800, 'exitDelay' => 259200],
    'batchTargets' => [$multiSendCallOnly],
    'approverIndex' => 0,   // this approver's index in the guard
]);
$done = $tq->safeGuard->waitForApproval($sent['requestId']);   // 5 minutes at most
$approval = $done['safeTx']['approval'];

// Check it yourself: your own transaction, the approver's key from the guard on chain, and what
// you are about to do with it: 'approve' (the default) runs it with execTransaction, 'schedule'
// sends a governance change (a delegatecall, a change to the Safe, a proxy upgrade) to the guard.
$purpose = $isGovernanceChange ? 'schedule' : 'approve';   // from your own decoding of $target
$check = SafeApproval::verify($target, $approval, $approverKey, ['approverIndex' => 0, 'purpose' => $purpose]);
if (!$check['valid']) {
    throw new RuntimeException("approval refused: {$check['reason']}");
}
if ($purpose === 'approve') {
    $signatures = SafeApproval::withApprovals($ownerSignatures, [$approval]);   // execTransaction(..., $signatures)
} else {
    $data = SafeApproval::scheduleCall($safe, $check['governanceHash'], [$approval]);   // a call to the guard; runs after govDelay
}
```

`SafeApproval::verify` makes the guard's check off chain, so a co-signer or your own server never has to trust Touchque: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature (ext-openssl). Without `purpose` only an ordinary approval (`approve`) passes: an approval to schedule a change covers no nonce or gas fields and is never one to execute, so name `'purpose' => 'schedule'` when that is what you send. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `rows` or `displayDigest` from your own decoding, rows the phone did not show. `reason` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `SafeApproval::safeTxHash`, `governanceHash`, `message` and `displayDigest` are public too.

## Errors

All SDK exceptions extend `TouchqueException`: `TouchqueAPIException`,
`TouchqueNetworkException`, `TouchqueConfigException`,
`TouchquePasskeyRequiredError`.

A feature your organization cannot use here throws a `TouchqueFeatureException` (still a `TouchqueAPIException`, status 403) with `getFeature()` (`device_risk`, `ai_agents`…) and `getFeatureReason()`: `TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException` or `TouchqueFeatureOffException` — not in its plan (an owner or admin adds it in the Touchque dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this Touchque deployment.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-Touchque-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](https://github.com/Touchque/touchque-php/blob/main/SECURITY.md) to report a vulnerability.

## Requirements

- PHP 7.4+ (CI runs PHP 8.2); `ext-curl` and `ext-json`, plus `ext-openssl` for approval proofs and `ext-sodium` for Ed25519 agent keys
- A [Touchque Dashboard](https://dashboard.touchque.com) account
- Laravel 10+ for the bundled middleware (optional)

## Logging

The SDK writes nothing to `error_log()` on its own. To see its own problems (a misconfigured guard, a failed `$onChallenge`, a relay without `getLoginUser`), pass a PSR-3 logger or a `callable(string $level, string $message)`: `new Config(logger: $logger)`, or `new Config(debug: true)` for `error_log()`. Lines carry an error's class and message, never the request. When `TouchqueMiddleware` cannot build its client (a missing key), there is no Config to carry your logger: it logs that once through Laravel's logger.

## License

MIT © [Touchque](https://touchque.com)

## Touchque Login (hosted sign-in)

Sign-up and sign-in pages for your own customers, on your brand, with OpenID Connect. See [support.touchque.com/touchque-login](https://support.touchque.com/touchque-login) for this SDK's client and a quickstart.
