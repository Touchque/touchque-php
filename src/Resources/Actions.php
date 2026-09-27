<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;

/** Action types ("LOGIN", "SEND_MONEY", …) — what a user is asked to
 * approve. Define them from code at start-up instead of clicking them into
 * the Dashboard. */
class Actions
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Creates the action type, or updates its name/description/critical flag.
     * Safe to call on every start-up: it never re-enables a type an admin disabled.
     */
    public function define(string $type, ?string $name = null, ?string $description = null, ?bool $critical = null): array
    {
        $body = ['type' => $type, 'name' => $name ?? $type];
        if ($description !== null) {
            $body['description'] = $description;
        }
        if ($critical !== null) {
            $body['critical'] = $critical;
        }
        return $this->http->post('/action-types', $body);
    }

    public function list(): array
    {
        return $this->http->get('/action-types');
    }
}
