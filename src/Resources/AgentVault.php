<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;

/**
 * The token vault for your agents ($tq->agents->vault): after your own OAuth flow with a person,
 * deposit their tokens; Touchque keeps them sealed and refreshes them, and the agents a connection
 * names get a short-lived access token (TouchqueAgent::getConnectionToken), never the refresh token.
 */
class AgentVault
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    public function listConnections(): array
    {
        return $this->http->get('/agents/vault/connections')['connections'];
    }

    /**
     * Adds or replaces a connection; clientSecret is kept when left out of a replacement.
     *
     * @param array $connection provider (google, microsoft, github, facebook, linkedin, x, oidc), clientId, clientSecret?, tenant?, issuer?, agentIds?
     */
    public function putConnection(string $name, array $connection): array
    {
        return $this->http->put('/agents/vault/connections/' . rawurlencode($name), $connection)['connection'];
    }

    /** Removes it, and every person's tokens kept for it. */
    public function removeConnection(string $name): array
    {
        return $this->http->delete('/agents/vault/connections/' . rawurlencode($name));
    }

    /**
     * Keeps a person's tokens (replacing earlier ones) after your own OAuth flow with them.
     *
     * @param array $tokens accessToken, refreshToken?, expiresIn?, scope?
     */
    public function deposit(string $connection, string $user, array $tokens): array
    {
        return $this->http->put('/agents/vault/accounts/' . rawurlencode($connection) . '/' . rawurlencode($user), $tokens)['account'];
    }

    /** A person's accounts in the vault (never a token). */
    public function listAccounts(string $user): array
    {
        return $this->http->get('/agents/vault/accounts', ['externalUsername' => $user])['accounts'];
    }

    /** Deletes a person's tokens: agents get nothing more for them there. */
    public function removeAccount(string $connection, string $user): void
    {
        $this->http->delete('/agents/vault/accounts/' . rawurlencode($connection) . '/' . rawurlencode($user));
    }
}
