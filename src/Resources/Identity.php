<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;
use Touchque\Resources\Identity\IdentityClients;
use Touchque\Resources\Identity\IdentityCrud;
use Touchque\Resources\Identity\IdentityCustomDomains;
use Touchque\Resources\Identity\IdentityJobs;
use Touchque\Resources\Identity\IdentityOrganizations;
use Touchque\Resources\Identity\IdentityUsers;

/**
 * Touchque Login Management API (`$tq->identity`): your customers' accounts,
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
    public IdentityCustomDomains $customDomains;

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
        $this->customDomains = new IdentityCustomDomains($http);
    }

    public function getTenant(): array
    {
        return $this->http->get('/identity/tenant');
    }

    /** Turns Touchque Login on (slug, displayName) or changes its settings. */
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
     * null: your brand name when the Mobile SDK is set up, else Touchque (`approverApp` in the tenant shows which).
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

    /**
     * The domain customer passkeys belong to (their relying party ID): null (or '') for none, each belongs to the host
     * it was made on; otherwise one of your verified custom domains, or a domain above one of them that your
     * organization verified (Organization → Domains: `acme.com` for `login.acme.com`), so passkeys keep working when
     * sign-in moves to another host under it. Answers the tenant, with `passkeyDomain`. A passkey belongs to its
     * domain for good: set it before customers make passkeys.
     *
     * Refusals throw TouchqueAPIException with the code in getData()['error']: 409 `passkeys_exist` when the change
     * would leave customer passkeys behind (getData()['count'] of them), 409 `not_your_domain` for a domain that is
     * not proved, 409 `organization_unavailable` when your organization's domains could not be read (try again),
     * 400 `invalid_request` with getData()['field'] `passkeyDomain` for a value that is not a domain. Before Touchque
     * Login is set up for the workspace: 400 `invalid_request` with getData()['field'] `slug` (set it up first with
     * updateTenant(['slug' => ..., 'displayName' => ...])).
     */
    public function setPasskeyDomain(?string $domain): array
    {
        return $this->http->put('/identity/tenant', ['passkeyDomain' => $domain]);
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

    /** Back to Touchque's transport. */
    public function removeDelivery(string $channel): array
    {
        return $this->http->delete('/identity/delivery/' . rawurlencode($channel));
    }

    /** One test message through the provider in use. */
    public function testDelivery(string $channel, string $to): array
    {
        return $this->http->post('/identity/delivery/' . rawurlencode($channel) . '/test', ['to' => $to]);
    }

    /**
     * Moving your customers in from your own user database: `url`, `enabled`, `active` (asked only while passwords
     * are on), `movedIn` (accounts made from it so far), `lastCall` (`at`, `event`, `ok`, `status`, `ms`, `error`;
     * null when there is none), `paused` (5 failures in a row pause it for a minute), `updatedAt` and `signing`.
     * Touchque POSTs `user_store.verify_password` {email, password} and `user_store.get_user` {email} to `url`,
     * signed like its webhooks: check each request with `$tq->webhook->verify(...)`, then answer
     * {"user": {"id", "email", "emailVerified", "name", ...}} or {"user": null} (the same for an unknown address and
     * a wrong password) within 5 seconds.
     */
    public function getUserStore(): array
    {
        return $this->http->get('/identity/user-store');
    }

    /**
     * Sets the endpoint and whether it is asked: ['url' => 'https://...', 'enabled' => true]. Either may be left out:
     * `url` is needed the first time, `enabled` is true the first time and kept after. Answers like getUserStore().
     * Needs passwords on (409 `passwords_off`).
     */
    public function setUserStore(array $store): array
    {
        return $this->http->put('/identity/user-store', $store);
    }

    /**
     * One signed `user_store.ping` to $url as given, without saving it, or to the endpoint set when $url is null or
     * '' (the body is then {}): `ok`, `error`, `ms`. A ping that fails is an answer (`ok` false, with why in
     * `error`), not an exception. 400 `invalid_request` (`field` url) for a URL Touchque does not take, or when none
     * is given and none is set.
     */
    public function testUserStore(?string $url = null): array
    {
        return $this->http->post('/identity/user-store/test', $url !== null && $url !== '' ? ['url' => $url] : []);
    }

    /** Stops asking your user database; accounts already moved in stay. Nothing set is not an error. */
    public function removeUserStore(): array
    {
        return $this->http->delete('/identity/user-store');
    }
}
