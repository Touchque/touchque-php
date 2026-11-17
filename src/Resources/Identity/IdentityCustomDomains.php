<?php

namespace Touchque\Resources\Identity;

use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Http\HttpClient;

/** `$tq->identity->customDomains`: your own sign-in domains (login.acme.com). */
class IdentityCustomDomains extends IdentityCrud
{
    public function __construct(HttpClient $http)
    {
        parent::__construct($http, '/identity/custom-domains', 'domains');
    }

    /**
     * The list as Touchque answers it, where list() returns only `domains`: `domains`, `verifiedDomains` (your
     * organization's verified domains, Organization → Domains; null when they could not be read) and `slugPasskeys`
     * (customer passkeys made on {slug}.login.touchque.com, which do not work on a custom domain). The three keys
     * are always there: a field missing from the answer reads as [], null and 0.
     *
     * @return array{domains: list<array<string, mixed>>, verifiedDomains: list<string>|null, slugPasskeys: int}
     */
    public function overview(): array
    {
        $answer = $this->http->get($this->base);
        return [
            'domains' => is_array($answer['domains'] ?? null) ? $answer['domains'] : [],
            'verifiedDomains' => is_array($answer['verifiedDomains'] ?? null) ? $answer['verifiedDomains'] : null,
            'slugPasskeys' => is_int($answer['slugPasskeys'] ?? null) ? $answer['slugPasskeys'] : 0,
        ] + $answer;
    }

    /**
     * The domain with this id, found in the list (the API has no read by id).
     *
     * @return array<string, mixed>
     * @throws TouchqueAPIException 404 `not_found` when there is none, as the API answers an unknown id
     *                              (getMessage() and getData()['error'] `not_found`).
     */
    public function get(string $id): array
    {
        foreach ($this->list() as $domain) {
            if (is_array($domain) && ($domain['id'] ?? null) === $id) {
                return $domain;
            }
        }
        throw new TouchqueAPIException('not_found', 404, ['error' => 'not_found', 'message' => 'No custom domain with this id']);
    }

    /**
     * Checks the DNS TXT record now (a domain your organization verified needs none) and the domain's DNS (`dns`);
     * answers the domain. Touchque also checks a new domain by itself every 5 minutes until `autoCheckUntil` (72
     * hours after it was added).
     *
     * @return array<string, mixed>
     */
    public function verify(string $id): array
    {
        return $this->http->post($this->base . '/' . rawurlencode($id) . '/verify', []);
    }
}
