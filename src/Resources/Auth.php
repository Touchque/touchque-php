<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;

class Auth
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Generate a new setup secret for a user.
     */
    public function generateSecret(string $externalUsername): array
    {
        return $this->http->post('/auth/generate-secret', [
            'externalUsername' => $externalUsername
        ]);
    }


    /**
     * Reset (regenerate) a user's secret.
     */
    public function resetSecret(string $externalUsername): array
    {
        return $this->http->post('/auth/secret/reset', [
            'externalUsername' => $externalUsername
        ]);
    }

    /**
     * Validate a setup secret code.
     * Mirrors the Node/Python/Go SDKs' `validateSecret`/`validate_secret`/`ValidateSecret`.
     */
    public function validateSecret(string $secret): array
    {
        return $this->http->post('/auth/secret/validate', [
            'secret' => $secret
        ]);
    }

    /**
     * Look up a user's link status without sending a push — `used` flips true
     * and `deviceId` is set once the mobile app scans the setup secret.
     * Returns `{ externalUsername, deviceId, used, frozen, createdAt, expireAt }`.
     * Throws TouchQueAPIException (404) if the user is unknown.
     */
    public function getUser(string $externalUsername): array
    {
        return $this->http->get('/users/' . rawurlencode($externalUsername));
    }
}
