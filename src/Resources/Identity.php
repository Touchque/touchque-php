<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;
use TouchQue\Resources\Identity\IdentityClients;
use TouchQue\Resources\Identity\IdentityCrud;
use TouchQue\Resources\Identity\IdentityJobs;
use TouchQue\Resources\Identity\IdentityOrganizations;
use TouchQue\Resources\Identity\IdentityUsers;

/**
 * TouchQue Login Management API (`$tq->identity`): your customers' accounts,
 * roles, business-customer organizations, apps, APIs, connections and the
 * tenant itself, from your server with your workspace key.
 *
 *     $found = $tq->identity->users->list(['q' => 'ayse']);
 *     $tq->identity->users->block($userId, 'chargeback');
 *     $job = $tq->identity->imports->start(['users' => [['email' => $e, 'passwordHash' => '$2b$10$...']]]);
 */
class Identity
{
    private HttpClient $http;
    public IdentityUsers $users;
    public IdentityJobs $imports;
    public IdentityJobs $exports;
    public IdentityCrud $roles;
    public IdentityOrganizations $organizations;
    public IdentityClients $clients;
    public IdentityCrud $apis;
    public IdentityCrud $connections;
    public IdentityCrud $customDomains;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
        $this->users = new IdentityUsers($http);
        $this->imports = new IdentityJobs($http, 'imports');
        $this->exports = new IdentityJobs($http, 'exports');
        $this->roles = new IdentityCrud($http, '/identity/roles', 'roles');
        $this->organizations = new IdentityOrganizations($http);
        $this->clients = new IdentityClients($http);
        $this->apis = new IdentityCrud($http, '/identity/apis', 'apis');
        $this->connections = new IdentityCrud($http, '/identity/connections', 'connections');
        $this->customDomains = new IdentityCrud($http, '/identity/custom-domains', 'domains');
    }

    public function getTenant(): array
    {
        return $this->http->get('/identity/tenant');
    }

    /** Turns TouchQue Login on (slug, displayName) or changes its settings. */
    public function updateTenant(array $body): array
    {
        return $this->http->put('/identity/tenant', $body);
    }

    public function rotateSigningKey(): array
    {
        return $this->http->post('/identity/tenant/signing-keys/rotate', []);
    }

    /**
     * The phone app the hosted pages tell customers to approve on ("Approve on the Acme app").
     * null: your brand name when the Mobile SDK is set up, else TouchQue (`approverApp` in the tenant shows which).
     */
    public function setApproverAppName(?string $name): array
    {
        return $this->http->put('/identity/tenant', ['branding' => ['approverAppName' => $name]]);
    }

    /**
     * Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads there and
     * refuses other calls. Turning it on needs a verified primary domain with a working certificate.
     */
    public function setCustomDomainOnly(bool $on): array
    {
        return $this->http->put('/identity/tenant', ['customDomainOnly' => $on]);
    }

    /** Checks a verified custom domain's certificate at the sign-in edge now (`certificate`: pending | active | error). */
    public function checkDomainCertificate(string $domainId): array
    {
        return $this->http->post('/identity/custom-domains/' . rawurlencode($domainId) . '/check-certificate', []);
    }

    /** The delivery log. Message text only in the local dev inbox. */
    public function outbox(array $params = []): array
    {
        return $this->http->get('/identity/outbox', $params);
    }

    /** Wrong passwords, suspicious addresses, bot challenge, breached passwords, new-browser notices, the risk engine. */
    public function getAttackProtection(): array
    {
        return $this->http->get('/identity/attack-protection');
    }

    /** Partial; the bot challenge's secret is write-only. */
    public function setAttackProtection(array $settings): array
    {
        return $this->http->put('/identity/attack-protection', $settings);
    }

    /** What attack protection caught lately. */
    public function attackEvents(array $params = []): array
    {
        return $this->http->get('/identity/attack-protection/events', $params);
    }

    /** The email and SMS providers; secrets never come back (secretsSet). */
    public function getDelivery(): array
    {
        return $this->http->get('/identity/delivery');
    }

    /**
     * Your own provider: email smtp, ses, postmark, sendgrid; sms twilio, netgsm.
     * ['provider' => 'postmark', 'from' => 'login@acme.com', 'serverToken' => ...]. A secret left out keeps its stored value.
     */
    public function setDelivery(string $channel, array $provider): array
    {
        return $this->http->put('/identity/delivery/' . rawurlencode($channel), $provider);
    }

    /** Back to TouchQue's transport. */
    public function removeDelivery(string $channel): array
    {
        return $this->http->delete('/identity/delivery/' . rawurlencode($channel));
    }

    /** One test message through the provider in use. */
    public function testDelivery(string $channel, string $to): array
    {
        return $this->http->post('/identity/delivery/' . rawurlencode($channel) . '/test', ['to' => $to]);
    }
}
