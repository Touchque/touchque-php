<?php

namespace Touchque;

use Touchque\Http\HttpClient;
use Touchque\Resources\Actions;
use Touchque\Resources\Agents;
use Touchque\Resources\Identity;
use Touchque\Resources\Mobile;
use Touchque\Resources\QrPairings;
use Touchque\Resources\DeviceRisk;
use Touchque\Resources\SafeGuard;
use Touchque\Resources\ActionTypes;
use Touchque\Resources\Auth;
use Touchque\Resources\Login;
use Touchque\Resources\Offline;
use Touchque\Resources\Risk;
use Touchque\Resources\Recovery;
use Touchque\Resources\Assist;
use Touchque\Resources\WebAuthn;
use Touchque\Resources\Webhook;

/**
 * Touchque SDK client.
 *
 *     // .env: TQ_API_KEY=tq_...  TQ_API_SECRET=...
 *     $tq = new Touchque();                                    // from the environment
 *     $tq = new Touchque(new Config($apiKey, $apiSecret));      // explicit
 *
 * One line per protected route — see `Touchque\Laravel\TouchqueMiddleware`,
 * or call `start()` / `check()` / `complete()` yourself for any framework.
 */
class Touchque
{
    public Auth $auth;
    public Login $login;
    public WebAuthn $webauthn;
    public Webhook $webhook;
    public Offline $offline;
    /** Action types: what users approve (LOGIN, SEND_MONEY…). Was `$actions` before 4.0. */
    public ActionTypes $actionTypes;
    /** Touchque Actions: your own code in the approval pipeline. */
    public Actions $actions;
    /** Silent sign-ins: should this sign-in ask the phone, and which browsers Touchque knows. */
    public Risk $risk;
    /** Never Locked Out: move a user whose phone is gone to a new phone, with colleagues vouching. */
    public Recovery $recovery;
    /** Help desk: IT working on a person's account in the open, and checks on their phone before sensitive actions. */
    public Assist $assist;
    /** AI agents as identities of their own: register (public key), suspend, revoke, kill switch. The agent itself uses TouchqueAgent. */
    public Agents $agents;
    /** Touchque Login: your customers' accounts, roles, organizations, apps, connections (Management API). */
    public Identity $identity;
    /** Mobile SDK: your own iOS/Android app approves for your users (enrollment tokens, devices, settings). */
    public Mobile $mobile;
    /** Pairing a browser by QR code: the phone that scans it is the one asked to approve. */
    public QrPairings $qrPairings;
    /** Device risk: the device on your sign-up, reset, sign-in or approval page (a paid add-on). */
    public DeviceRisk $deviceRisk;
    /** Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard. */
    public SafeGuard $safeGuard;

    private Config $config;

    /** @internal The SDK's own log (silent unless the Config has a logger or debug). */
    public function log(string $level, string $message): void
    {
        $this->config->log($level, $message);
    }

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? new Config();
        $httpClient = new HttpClient($this->config);

        $this->auth = new Auth($httpClient);
        $this->login = new Login($httpClient);
        $this->webauthn = new WebAuthn($httpClient);
        $this->webhook = new Webhook($this->config);
        $this->offline = new Offline($httpClient);
        $this->actionTypes = new ActionTypes($httpClient);
        $this->actions = new Actions($httpClient);
        $this->risk = new Risk($httpClient);
        $this->recovery = new Recovery($httpClient);
        $this->assist = new Assist($httpClient);
        $this->agents = new Agents($httpClient);
        $this->identity = new Identity($httpClient);
        $this->mobile = new Mobile($httpClient);
        $this->qrPairings = new QrPairings($httpClient);
        $this->deviceRisk = new DeviceRisk($httpClient);
        $this->safeGuard = new SafeGuard($httpClient);
    }

    /** @internal used by Guard/Steps to sign/verify the browser-facing token. */
    public function getApiSecret(): string
    {
        return $this->config->getApiSecret();
    }

    /**
     * Starts an approval and returns immediately — show the step in your UI.
     * `waiting` + `number`: show the number, the user picks it on the phone.
     * `enroll`: show `enroll['qrCodeDataUrl']` so the user links the Touchque app first.
     * `$browserProof` (silent sign-ins): the `X-Touchque-Browser` header, passed through
     * untouched; once the user approves, Touchque knows this browser.
     */
    public function start(string $action, string $user, ?array $details = null, ?string $referenceId = null, ?string $ip = null, ?string $userAgent = null, ?string $browserProof = null): array
    {
        return Steps::start($this, $action, $user, $details, $referenceId, $ip, $userAgent, true, $browserProof);
    }

    /** Where a started approval is now: waiting, approved, rejected, expired… */
    public function check(string $requestId): array
    {
        return Steps::check($this, $requestId);
    }

    /**
     * Uses an approved request exactly once, after checking it is for this
     * user, action and transaction. Call it right before doing the protected thing.
     */
    public function complete(string $requestId, string $user, string $action, ?array $details = null, ?string $referenceId = null): array
    {
        return Steps::complete($this, $requestId, $user, $action, $details, $referenceId);
    }
}
