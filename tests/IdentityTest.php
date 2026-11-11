<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Touchque;

/** $tq->identity (Touchque Login Management API) against the shared fake API, which checks every signature. */
class IdentityTest extends TestCase
{
    private static FakeApi $api;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    public function testCalls(): void
    {
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
        $tq->identity->users->list(['q' => 'ayse', 'limit' => 10]);
        $tq->identity->users->create(['email' => 'a@x.com', 'passwordHash' => '$2b$10$abc']);
        $tq->identity->users->update('usr_1', ['appMetadata' => ['plan' => null]]);
        $tq->identity->users->block('usr_1', 'fraud');
        $tq->identity->users->delete('usr_1');
        $tq->identity->users->resetMfa('usr_1');
        $tq->identity->users->passwordReset('usr_1', false);
        $tq->identity->users->addRoles('usr_1', ['rol_1'], 'org_1');
        $tq->identity->users->removeRole('usr_1', 'rol_1', 'org_1');
        $tq->identity->imports->start(['users' => [['email' => 'b@x.com']], 'upsert' => true]);
        $tq->identity->organizations->invite('org_1', ['email' => 'c@x.com', 'clientId' => 'cli', 'roleIds' => ['rol_1']]);
        $this->assertSame([], $tq->identity->roles->list());
        $tq->identity->updateTenant(['slug' => 'acme', 'displayName' => 'Acme']);
        $this->assertSame('done', $tq->identity->exports->wait('job_1', 0.001)['status']);
        $tq->identity->setDelivery('email', ['provider' => 'postmark', 'from' => 'login@acme.test', 'serverToken' => 'pm']);
        $tq->identity->testDelivery('sms', '+905321234567');
        $tq->identity->setAttackProtection(['bot' => ['provider' => 'turnstile', 'siteKey' => 'k', 'secret' => 's', 'mode' => 'risky']]);
        $tq->identity->setApproverAppName('Acme Pay');
        $tq->identity->setCustomDomainOnly(true);
        $tq->identity->checkDomainCertificate('dom_1');
        $tq->identity->clients->rotateSecret('cli_1');
        $tq->identity->users->endSession('usr_1', 'ses_1');
        $this->assertSame('{"ok":true}', $tq->identity->exports->file('job_1'));

        $calls = array_values(array_filter(self::$api->calls(), fn ($c) => strpos($c['path'], '/identity') === 0));
        $this->assertSame([
            'GET /identity/users?limit=10&q=ayse',
            'POST /identity/users',
            'PATCH /identity/users/usr_1',
            'POST /identity/users/usr_1/block',
            'DELETE /identity/users/usr_1',
            'DELETE /identity/users/usr_1/mfa',
            'POST /identity/users/usr_1/password-reset',
            'POST /identity/users/usr_1/roles',
            'DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1',
            'POST /identity/users-imports',
            'POST /identity/organizations/org_1/invitations',
            'GET /identity/roles',
            'PUT /identity/tenant',
            'GET /identity/users-exports/job_1',
            'PUT /identity/delivery/email',
            'POST /identity/delivery/sms/test',
            'PUT /identity/attack-protection',
            'PUT /identity/tenant',
            'PUT /identity/tenant',
            'POST /identity/custom-domains/dom_1/check-certificate',
            'POST /identity/clients/cli_1/rotate-secret',
            'DELETE /identity/users/usr_1/sessions/ses_1',
            'GET /identity/users-exports/job_1/file',
        ], array_map(fn ($c) => $c['method'] . ' ' . $c['url'], $calls));
        $this->assertSame(['branding' => ['approverAppName' => 'Acme Pay']], $calls[17]['body']);
        $this->assertSame(['customDomainOnly' => true], $calls[18]['body']);
        $this->assertSame(['email' => 'a@x.com', 'passwordHash' => '$2b$10$abc'], $calls[1]['body']);
        $this->assertSame(['appMetadata' => ['plan' => null]], $calls[2]['body']);
        $this->assertSame(['roleIds' => ['rol_1'], 'organizationId' => 'org_1'], $calls[7]['body']);
    }

    public function testBooleanFiltersGoAsTrueAndFalse(): void
    {
        // The API honours only the strings 'true' and 'false'; 1/0 would list everyone.
        self::$api->reset();
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
        $tq->identity->users->list(['blocked' => true, 'emailVerified' => false]);
        $calls = self::$api->calls();
        $this->assertSame('GET /identity/users?blocked=true&emailVerified=false', $calls[0]['method'] . ' ' . $calls[0]['url']);
    }
}
