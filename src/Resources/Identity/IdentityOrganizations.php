<?php

namespace Touchque\Resources\Identity;

use Touchque\Http\HttpClient;

/** `$tq->identity->organizations`: business customers, their members and invitations. */
class IdentityOrganizations extends IdentityCrud
{
    public function __construct(HttpClient $http)
    {
        parent::__construct($http, '/identity/organizations', 'organizations');
    }

    public function members(string $orgId): array
    {
        return $this->http->get($this->base . '/' . rawurlencode($orgId) . '/members');
    }

    public function addMembers(string $orgId, array $userIds): array
    {
        return $this->http->post($this->base . '/' . rawurlencode($orgId) . '/members', ['userIds' => $userIds]);
    }

    public function removeMember(string $orgId, string $userId): array
    {
        return $this->http->delete($this->base . '/' . rawurlencode($orgId) . '/members/' . rawurlencode($userId));
    }

    public function setConnections(string $orgId, array $connections): array
    {
        return $this->http->put($this->base . '/' . rawurlencode($orgId) . '/connections', ['connections' => $connections]);
    }

    public function invitations(string $orgId): array
    {
        return $this->http->get($this->base . '/' . rawurlencode($orgId) . '/invitations');
    }

    /** The link opens the app's sign-in route (initiateLoginUri) with organization and invitation. */
    public function invite(string $orgId, array $invitation): array
    {
        return $this->http->post($this->base . '/' . rawurlencode($orgId) . '/invitations', $invitation);
    }

    public function revokeInvitation(string $orgId, string $invitationId): array
    {
        return $this->http->delete($this->base . '/' . rawurlencode($orgId) . '/invitations/' . rawurlencode($invitationId));
    }
}
