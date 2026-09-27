<?php

namespace TouchQue;

use TouchQue\Http\HttpClient;
use TouchQue\Resources\Actions;
use TouchQue\Resources\Auth;
use TouchQue\Resources\Login;
use TouchQue\Resources\Offline;
use TouchQue\Resources\WebAuthn;
use TouchQue\Resources\Webhook;

/**
 * TouchQue SDK client.
 *
 *     // .env: TQ_API_KEY=tq_...  TQ_API_SECRET=...
 *     $tq = new TouchQue();                                    // from the environment
 *     $tq = new TouchQue(new Config($apiKey, $apiSecret));      // explicit
 *
 * One line per protected route — see `TouchQue\Laravel\TouchQueMiddleware`,
 * or call `start()` / `check()` / `complete()` yourself for any framework.
 */
class TouchQue
{
    public Auth $auth;
    public Login $login;
    public WebAuthn $webauthn;
    public Webhook $webhook;
    public Offline $offline;
    public Actions $actions;

    private Config $config;

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? new Config();
        $httpClient = new HttpClient($this->config);

        $this->auth = new Auth($httpClient);
        $this->login = new Login($httpClient);
        $this->webauthn = new WebAuthn($httpClient);
        $this->webhook = new Webhook($this->config);
        $this->offline = new Offline($httpClient);
        $this->actions = new Actions($httpClient);
    }

    /** @internal used by Guard/Steps to sign/verify the browser-facing token. */
    public function getApiSecret(): string
    {
        return $this->config->getApiSecret();
    }

    /**
     * Starts an approval and returns immediately — show the step in your UI.
     * `waiting` + `number`: show the number, the user picks it on the phone.
     * `enroll`: show `enroll['qrCodeDataUrl']` so the user links the TouchQue app first.
     */
    public function start(string $action, string $user, ?array $details = null, ?string $referenceId = null, ?string $ip = null, ?string $userAgent = null): array
    {
        return Steps::start($this, $action, $user, $details, $referenceId, $ip, $userAgent);
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
