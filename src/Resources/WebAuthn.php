<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;

/**
 * WebAuthn / FIDO2 (passkey) — a phishing-resistant approval path alongside the
 * push + device flow (`Login::verify`).
 *
 * Server-to-server, like every other resource here: the passkey ceremony runs
 * in the browser (`navigator.credentials.create()` / `.get()`, or
 * `@touchque/web`); your backend collects that JSON and relays it through these
 * methods. There is no client-side ceremony in this SDK.
 */
class WebAuthn
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    // ── registration ──────────────────────────────────────────────────────
    /**
     * Step 1: options for `navigator.credentials.create()`.
     * `$discoverable = true` registers a resident credential (forced UV) — the
     * shape a passwordless-primary login authenticates against.
     */
    public function registerOptions(string $externalUsername, bool $discoverable = false): array
    {
        $body = ['externalUsername' => $externalUsername];
        if ($discoverable) {
            $body['discoverable'] = true;
        }
        return $this->http->post('/webauthn/register/options', $body);
    }

    /**
     * Step 2: verify the browser's registration response. Returns
     * `{ verified, credentialId }`.
     */
    public function registerVerify(string $externalUsername, array $response, ?string $label = null): array
    {
        $body = ['externalUsername' => $externalUsername, 'response' => $response];
        if ($label !== null) {
            $body['label'] = $label;
        }
        return $this->http->post('/webauthn/register/verify', $body);
    }

    // ── second-factor authentication (against a pending LoginRequest) ──────
    /** Step 1: options for `navigator.credentials.get()`, scoped to `$requestId`. */
    public function authenticateOptions(string $requestId): array
    {
        return $this->http->post('/webauthn/login/options', ['requestId' => $requestId]);
    }

    /** Step 2: verify the assertion — approves the LoginRequest. Returns `{ success, message }`. */
    public function authenticateVerify(string $requestId, array $response): array
    {
        return $this->http->post('/webauthn/login/verify', ['requestId' => $requestId, 'response' => $response]);
    }

    // ── passwordless-primary login ────────────────────────────────────────
    /**
     * Step 1 of a passwordless-primary login. Requires
     * `TenantPolicy.passwordlessLoginEnabled`. A 404 `no_passkey_registered`
     * means the user has no passkey — fall back to password login.
     * Returns `{ attemptId, options }`.
     */
    public function primaryOptions(string $externalUsername): array
    {
        return $this->http->post('/webauthn/authenticate/primary/options', ['externalUsername' => $externalUsername]);
    }

    /**
     * Step 2 of a passwordless-primary login. On `success = true` the returned
     * `requestId` is a CONFIRMED LoginRequest. On `success = false` with
     * `requiresStepUp = true`, start the normal `Login::request` flow instead.
     */
    public function primaryVerify(string $attemptId, array $response): array
    {
        return $this->http->post('/webauthn/authenticate/primary/verify', ['attemptId' => $attemptId, 'response' => $response]);
    }

    // ── credential management ────────────────────────────────────────────
    /** List a user's registered credentials (metadata only, no key material). */
    public function listCredentials(string $externalUsername): array
    {
        return $this->http->get('/webauthn/credentials', ['externalUsername' => $externalUsername]);
    }

    /**
     * Remove a registered credential. Pass `$externalUsername` to scope the
     * deletion to that user (recommended: without it, any credential id
     * your API key can reach is deletable). Returns `{ deleted: bool }`.
     */
    public function deleteCredential(string $credentialRecordId, ?string $externalUsername = null): array
    {
        $path = '/webauthn/credentials/' . rawurlencode($credentialRecordId);
        if ($externalUsername !== null) {
            $path .= '?externalUsername=' . rawurlencode($externalUsername);
        }
        return $this->http->delete($path);
    }
}
