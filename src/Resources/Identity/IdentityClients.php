<?php

namespace TouchQue\Resources\Identity;

use TouchQue\Http\HttpClient;

/** TouchQue Login applications (`$tq->identity->clients`). */
class IdentityClients extends IdentityCrud
{
    public function __construct(HttpClient $http)
    {
        parent::__construct($http, '/identity/clients', 'clients');
    }

    /** A new client secret, shown once in the answer (`clientSecret`); the old one stops working. */
    public function rotateSecret(string $clientId): array
    {
        return $this->http->post($this->base . '/' . rawurlencode($clientId) . '/rotate-secret', []);
    }
}
