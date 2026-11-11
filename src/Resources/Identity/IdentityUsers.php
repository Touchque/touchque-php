<?php

namespace Touchque\Resources\Identity;

use Touchque\Http\HttpClient;

/** `$tq->identity->users`: a tenant's customer accounts. */
class IdentityUsers
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    private static function id(string $v): string
    {
        return rawurlencode($v);
    }

    /** @param array $params q, blocked, emailVerified, connection, organization, limit, cursor */
    public function list(array $params = []): array
    {
        return $this->http->get('/identity/users', $params);
    }

    public function get(string $userId): array
    {
        return $this->http->get('/identity/users/' . self::id($userId));
    }

    /**
     * @param array $user email and: password, passwordHash (bcrypt/argon2), customPasswordHash, emailVerified,
     *                    name, givenName, familyName, phone, locale, userMetadata, appMetadata, sendVerificationEmail
     */
    public function create(array $user): array
    {
        return $this->http->post('/identity/users', $user);
    }

    /** Metadata is merged; a key set to null is removed. */
    public function update(string $userId, array $changes): array
    {
        return $this->http->patch('/identity/users/' . self::id($userId), $changes);
    }

    /** Erasure (KVKK/GDPR): the account and every workspace row that names it. */
    public function delete(string $userId): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId));
    }

    public function block(string $userId, ?string $reason = null): array
    {
        return $this->http->post('/identity/users/' . self::id($userId) . '/block', $reason !== null ? ['reason' => $reason] : []);
    }

    public function unblock(string $userId): array
    {
        return $this->http->post('/identity/users/' . self::id($userId) . '/unblock', []);
    }

    /** Everything about the person (KVKK/GDPR access request); never hashes. */
    public function export(string $userId): array
    {
        return $this->http->get('/identity/users/' . self::id($userId) . '/export');
    }

    public function sessions(string $userId): array
    {
        return $this->http->get('/identity/users/' . self::id($userId) . '/sessions');
    }

    /** Signs the person out of one session (the others stay). */
    public function endSession(string $userId, string $sessionId): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId) . '/sessions/' . self::id($sessionId));
    }

    public function signOutEverywhere(string $userId): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId) . '/sessions');
    }

    /** Removes passkeys, unlinks the Touchque app, turns email codes off, signs out everywhere. */
    public function resetMfa(string $userId): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId) . '/mfa');
    }

    /** Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on). */
    public function connectedAccounts(string $userId): array
    {
        return $this->http->get('/identity/users/' . self::id($userId) . '/connected-accounts');
    }

    /** Deletes the stored tokens: apps stop using the account for the user; signing in with it stays. */
    public function disconnectAccount(string $userId, string $accountId): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId) . '/connected-accounts/' . self::id($accountId));
    }

    public function unlinkIdentity(string $userId, string $identityId, bool $force = false): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId) . '/identities/' . self::id($identityId) . ($force ? '?force=true' : ''));
    }

    public function sendVerificationEmail(string $userId, ?string $returnTo = null): array
    {
        return $this->http->post('/identity/users/' . self::id($userId) . '/verification-email', $returnTo !== null ? ['returnTo' => $returnTo] : []);
    }

    /** $sendEmail false: the link comes back for you to deliver. */
    public function passwordReset(string $userId, bool $sendEmail = true, ?int $ttlSec = null): array
    {
        return $this->http->post('/identity/users/' . self::id($userId) . '/password-reset', array_filter(['sendEmail' => $sendEmail, 'ttlSec' => $ttlSec], fn ($v) => $v !== null));
    }

    public function roles(string $userId): array
    {
        return $this->http->get('/identity/users/' . self::id($userId) . '/roles');
    }

    public function addRoles(string $userId, array $roleIds, ?string $organizationId = null): array
    {
        return $this->http->post('/identity/users/' . self::id($userId) . '/roles', array_filter(['roleIds' => $roleIds, 'organizationId' => $organizationId], fn ($v) => $v !== null));
    }

    public function removeRole(string $userId, string $roleId, ?string $organizationId = null): array
    {
        return $this->http->delete('/identity/users/' . self::id($userId) . '/roles/' . self::id($roleId) . ($organizationId !== null ? '?organizationId=' . self::id($organizationId) : ''));
    }

    public function logs(string $userId, ?int $limit = null): array
    {
        return $this->http->get('/identity/users/' . self::id($userId) . '/logs', $limit !== null ? ['limit' => $limit] : []);
    }
}
