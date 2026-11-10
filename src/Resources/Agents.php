<?php

namespace TouchQue\Resources;

use TouchQue\ApprovalToken;
use TouchQue\Exceptions\TouchQueApprovalMismatchException;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Http\HttpClient;

/**
 * AI agents as identities of their own (`$tq->agents`): register an agent
 * with its PUBLIC key, give it an accountable owner and the action types it
 * may ask approvals for, suspend, revoke or stop every agent at once. The
 * agent itself never gets your API key: it signs in with its own key
 * (`TouchQue\TouchQueAgent`).
 *
 *     $keys = AgentKeys::generate();                       // where the agent runs
 *     $agent = $tq->agents->create('Invoice bot', ['PAY_INVOICE'], ['publicKey' => $keys['publicJwk']]);
 */
class Agents
{
    private HttpClient $http;
    /** The token vault: people's tokens at other services, for your agents. */
    public AgentVault $vault;
    private ?array $jwks = null;
    private int $jwksAt = 0;
    private ?string $audience = null;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
        $this->vault = new AgentVault($http);
    }

    /**
     * Uses an agent's approval exactly once, right before you execute: checks
     * $expect (user, type, authorizationDetails) against the token first
     * (nothing is used on a mismatch), then TouchQue checks the token and marks
     * it used, and the answer is checked again.
     */
    public function redeemApproval(string $token, array $expect = []): array
    {
        ApprovalToken::assertMatches(ApprovalToken::decode($token)['claims'], $expect);
        $approval = $this->http->post('/agents/approvals/redeem', ['token' => $token])['approval'];
        ApprovalToken::assertMatches(['sub' => $approval['externalUsername'] ?? null, 'type' => $approval['type'] ?? null, 'authorization_details' => $approval['authorizationDetails'] ?? null], $expect);
        return $approval;
    }

    /**
     * The aud of this workspace's approval tokens (touchque:workspace:<id>),
     * from GET /agents/approval-audience; asked once, then kept.
     */
    public function approvalAudience(): string
    {
        if ($this->audience === null) {
            $audience = $this->http->get('/agents/approval-audience')['audience'] ?? null;
            if (!is_string($audience) || $audience === '') {
                throw new TouchQueApprovalMismatchException("Touchque did not name this workspace's approval audience");
            }
            $this->audience = $audience;
        }
        return $this->audience;
    }

    /**
     * Verifies an approval token offline (TouchQue's published keys, expiry,
     * aud, $expect). aud must be this workspace's: $audience defaults to
     * approvalAudience(), and a token without aud or for another workspace is
     * refused. It does not make the token single-use: redeemApproval does.
     */
    public function verifyApprovalToken(string $token, ?string $audience = null, array $expect = []): array
    {
        if ($audience === null || $audience === '') {
            $audience = $this->approvalAudience();
        }
        if ($this->jwks === null || time() - $this->jwksAt > 300) {
            $this->jwks = $this->http->get('/agents/jwks.json');
            $this->jwksAt = time();
        }
        try {
            return ApprovalToken::verifyWith($token, $this->jwks, $audience, $expect);
        } catch (TouchQueApprovalMismatchException $e) {
            if (strpos($e->getMessage(), 'unknown key') === false) {
                throw $e;
            }
            $this->jwks = $this->http->get('/agents/jwks.json');
            $this->jwksAt = time();
            return ApprovalToken::verifyWith($token, $this->jwks, $audience, $expect);
        }
    }

    /** Refuses a private key before it leaves this process. */
    private static function publicOnly(array $jwk): array
    {
        if (array_key_exists('d', $jwk)) {
            throw new TouchQueConfigException("Pass the agent's PUBLIC key: this one has private parts (d). The private key must stay where the agent runs.");
        }
        return $jwk;
    }

    /**
     * Registers an agent (needs the `agents:write` scope).
     * `$options`: publicKey | publicKeys, description, ownerEmail (the accountable member; default the
     * API key's creator, the agent stops when they leave), platform, reviewInDays (1-365, default 90).
     */
    public function create(string $name, array $allowedTypes, array $options = []): array
    {
        $body = ['name' => $name, 'allowedTypes' => array_values($allowedTypes)];
        foreach (['description', 'ownerEmail', 'platform', 'reviewInDays'] as $key) {
            if (isset($options[$key])) {
                $body[$key] = $options[$key];
            }
        }
        if (isset($options['publicKey'])) {
            $body['publicKey'] = self::publicOnly($options['publicKey']);
        }
        if (isset($options['publicKeys'])) {
            $body['publicKeys'] = array_map([self::class, 'publicOnly'], $options['publicKeys']);
        }
        return $this->http->post('/agents', $body)['agent'];
    }

    /** `['agents' => [...], 'killSwitch' => [...]]`. */
    public function list(?string $status = null): array
    {
        return $this->http->get('/agents', $status ? ['status' => $status] : []);
    }

    public function get(string $agentId): array
    {
        return $this->http->get('/agents/' . rawurlencode($agentId))['agent'];
    }

    /** Changes, hands over (ownerEmail) or renews (reviewInDays) an agent. */
    public function update(string $agentId, array $changes): array
    {
        return $this->http->patch('/agents/' . rawurlencode($agentId), $changes)['agent'];
    }

    /** Adds a key (rotation: add the new one, move the agent to it, then remove the old one). */
    public function addKey(string $agentId, array $publicKey): array
    {
        return $this->http->post('/agents/' . rawurlencode($agentId) . '/keys', ['publicKey' => self::publicOnly($publicKey)])['agent'];
    }

    /** Removes a key; tokens the agent got with it stop at once. */
    public function removeKey(string $agentId, string $kid): array
    {
        return $this->http->delete('/agents/' . rawurlencode($agentId) . '/keys/' . rawurlencode($kid))['agent'];
    }

    /** Stops an agent at once (its tokens too) until resumed. */
    public function suspend(string $agentId, ?string $reason = null): array
    {
        return $this->http->post('/agents/' . rawurlencode($agentId) . '/suspend', $reason ? ['reason' => $reason] : [])['agent'];
    }

    public function resume(string $agentId): array
    {
        return $this->http->post('/agents/' . rawurlencode($agentId) . '/resume', [])['agent'];
    }

    /** Revokes an agent for good (the record stays for the audit trail). */
    public function revoke(string $agentId): array
    {
        return $this->http->delete('/agents/' . rawurlencode($agentId))['agent'];
    }

    /**
     * Sets the agent's budgets, amounts, recipients and background rule (a full
     * replacement; left-out fields take the defaults): requestsPer10Min,
     * requestsPerUserPer10Min, amountPerRequest / amountPerDay (['TRY' => '1000.00']),
     * background (non_critical | never), newRecipients (ask | deny), recipientAllowlist,
     * fourEyes, requirePasskeyAbove (['TRY' => '10000.00']: over it the person approves
     * with a passkey on your page, never on the phone or with a mandate).
     */
    public function setPolicy(string $agentId, array $policy): array
    {
        return $this->http->put('/agents/' . rawurlencode($agentId) . '/policy', ['policy' => $policy])['agent'];
    }

    /**
     * The workspace's agent events for a SIEM, oldest first: ['events', 'next', 'hasMore'].
     * Keep 'next' and pass it as $after; the first call reads from $since (ISO 8601;
     * default the last 24 hours).
     */
    public function listEvents(?string $after = null, ?string $since = null, ?int $limit = null): array
    {
        $query = array_filter(['after' => $after, 'since' => $since, 'limit' => $limit], static fn ($v) => $v !== null);
        return $this->http->get('/agents/events', $query);
    }

    /** The workspace's policy: every agent's floor (an agent's own policy can only make it stricter). */
    public function getWorkspacePolicy(): array
    {
        return $this->http->get('/agents/workspace-policy')['policy'];
    }

    /** Sets the workspace's policy (a full replacement; a field left out sets no floor). */
    public function setWorkspacePolicy(array $policy): array
    {
        return $this->http->put('/agents/workspace-policy', ['policy' => $policy])['policy'];
    }

    /** The people who stopped this agent asking them (reason not_me, coached or rejections). */
    public function listBlocks(string $agentId): array
    {
        return $this->http->get('/agents/' . rawurlencode($agentId) . '/blocks')['blocks'];
    }

    /** Lets the agent ask this person again (check with them first). */
    public function liftBlock(string $agentId, string $user): void
    {
        $this->http->delete('/agents/' . rawurlencode($agentId) . '/blocks/' . rawurlencode($user));
    }

    /** An agent's mandates, optionally one person's. */
    public function listMandates(string $agentId, ?string $user = null): array
    {
        return $this->http->get('/agents/' . rawurlencode($agentId) . '/mandates', $user ? ['externalUsername' => $user] : [])['mandates'];
    }

    /** Ends an agent's mandate at once. */
    public function revokeMandate(string $agentId, string $mandateId): array
    {
        return $this->http->post('/agents/' . rawurlencode($agentId) . '/mandates/' . rawurlencode($mandateId) . '/revoke', []);
    }

    /** Stops (true) or restarts (false) every agent of the workspace at once. */
    public function setKillSwitch(bool $engaged, ?string $reason = null): array
    {
        $body = ['engaged' => $engaged];
        if ($reason) {
            $body['reason'] = $reason;
        }
        return $this->http->put('/agents/kill-switch', $body)['killSwitch'];
    }
}
