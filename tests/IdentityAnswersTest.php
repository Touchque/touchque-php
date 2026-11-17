<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueFeatureException;
use Touchque\Exceptions\TouchqueWebhookReplayException;
use Touchque\Touchque;
use Touchque\Webhook\MemoryReplayCache;

/**
 * $tq->identity against a local server that answers what the Touchque Login Management API answers
 * (its tenant, user store and custom domain routes): the passkey
 * domain, the user store and custom domains, with the exact bodies the SDK sends, the answers it hands
 * back and the refusals it throws. The shared fake API (IdentityTest) checks the signatures.
 */
class IdentityAnswersTest extends TestCase
{
    /** @var resource|null */
    private $server = null;
    private ?string $dir = null;

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            proc_terminate($this->server);
            proc_close($this->server);
        }
        if ($this->dir !== null) {
            foreach ((array)glob($this->dir . '/*') as $file) {
                @unlink((string)$file);
            }
            @rmdir($this->dir);
        }
    }

    /**
     * A server on 127.0.0.1 (php -S) answering each "METHOD /path" (the path as sent, percent-encoding kept)
     * with its canned [status, body] answers in turn (the last one again after that; 204 sends no body).
     */
    private function server(array $answers): Touchque
    {
        $this->dir = sys_get_temp_dir() . '/tq-identity-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
        file_put_contents($this->dir . '/answers.json', json_encode($answers));
        file_put_contents($this->dir . '/router.php', <<<'PHP'
<?php
$key = $_SERVER['REQUEST_METHOD'] . ' ' . (string)parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
file_put_contents(__DIR__ . '/seen.jsonl', json_encode(['call' => $key, 'body' => file_get_contents('php://input')]) . "\n", FILE_APPEND);
$counter = __DIR__ . '/n-' . md5($key);
$n = is_file($counter) ? (int)file_get_contents($counter) : 0;
file_put_contents($counter, (string)($n + 1));
$list = json_decode((string)file_get_contents(__DIR__ . '/answers.json'), true)[$key] ?? [[404, ['error' => 'no_route']]];
[$status, $body] = $list[min($n, count($list) - 1)];
http_response_code($status);
if ($status !== 204) {
    header('Content-Type: application/json');
    echo json_encode($body);
}
PHP
        );
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int)substr((string)strrchr((string)stream_socket_get_name($probe, false), ':'), 1);
        fclose($probe);
        $this->server = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$port}", $this->dir . '/router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100000);
        }
        return new Touchque(new Config('tq_test_key', 'test_secret', "http://127.0.0.1:{$port}"));
    }

    /** What the server got, in order: ['call' => 'PUT /identity/tenant', 'body' => raw body]. */
    private function seen(): array
    {
        $file = (string)$this->dir . '/seen.jsonl';
        $lines = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES) : [];
        return array_map(static fn ($l) => json_decode($l, true), (array)$lines);
    }

    /** Runs $call, which must throw the API's refusal: a TouchqueAPIException (never a feature exception). */
    private function refusal(callable $call): TouchqueAPIException
    {
        try {
            $call();
        } catch (TouchqueAPIException $e) {
            $this->assertNotInstanceOf(TouchqueFeatureException::class, $e);
            return $e;
        }
        $this->fail('the refusal must throw');
    }

    public function testPasskeyDomain(): void
    {
        $tenant = ['slug' => 'acme', 'issuer' => 'https://login.acme.com', 'customDomainOnly' => false];
        $tq = $this->server(['PUT /identity/tenant' => [
            [200, $tenant + ['passkeyDomain' => 'acme.com']],
            [200, $tenant + ['passkeyDomain' => null]],
            [409, ['error' => 'passkeys_exist', 'field' => 'passkeyDomain', 'count' => 2, 'message' => '2 customer passkeys belong to the current setting and would stop working']],
            [409, ['error' => 'not_your_domain', 'field' => 'passkeyDomain', 'message' => 'example.org must be one of your verified custom domains, or a domain above one that your organization verified (Organization → Domains)']],
            [409, ['error' => 'organization_unavailable', 'field' => 'passkeyDomain', 'message' => 'Your organization’s verified domains could not be read; try again']],
            [400, ['error' => 'invalid_request', 'field' => 'passkeyDomain', 'message' => 'passkeyDomain must be a domain like example.com, or null']],
            // Touchque Login not set up yet: the PUT would create the tenant, which needs a slug first.
            [400, ['error' => 'invalid_request', 'field' => 'slug', 'message' => 'slug must be 3–63 lowercase letters, digits or hyphens']],
        ]]);

        $this->assertSame($tenant + ['passkeyDomain' => 'acme.com'], $tq->identity->setPasskeyDomain('acme.com'));
        // null is sent (not left out): it clears the passkey domain.
        $this->assertNull($tq->identity->setPasskeyDomain(null)['passkeyDomain']);

        $e = $this->refusal(fn () => $tq->identity->setPasskeyDomain('login.acme.com'));
        $this->assertSame(409, $e->getStatus());
        $this->assertSame('passkeys_exist', $e->getData()['error']);
        $this->assertSame('passkeys_exist', $e->getMessage());
        $this->assertSame(2, $e->getData()['count']);
        $this->assertSame('passkeyDomain', $e->getData()['field']);
        $this->assertStringContainsString('would stop working', $e->getData()['message']);

        $e = $this->refusal(fn () => $tq->identity->setPasskeyDomain('example.org'));
        $this->assertSame([409, 'not_your_domain', 'passkeyDomain'], [$e->getStatus(), $e->getData()['error'], $e->getData()['field']]);
        $e = $this->refusal(fn () => $tq->identity->setPasskeyDomain('acme.com'));
        $this->assertSame([409, 'organization_unavailable'], [$e->getStatus(), $e->getData()['error']]);
        $e = $this->refusal(fn () => $tq->identity->setPasskeyDomain('com'));
        $this->assertSame([400, 'invalid_request', 'passkeyDomain'], [$e->getStatus(), $e->getData()['error'], $e->getData()['field']]);
        $e = $this->refusal(fn () => $tq->identity->setPasskeyDomain('acme.com'));
        $this->assertSame([400, 'invalid_request', 'slug'], [$e->getStatus(), $e->getData()['error'], $e->getData()['field']]);

        $this->assertSame([
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":"acme.com"}'],
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":null}'],
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":"login.acme.com"}'],
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":"example.org"}'],
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":"acme.com"}'],
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":"com"}'],
            ['call' => 'PUT /identity/tenant', 'body' => '{"passkeyDomain":"acme.com"}'],
        ], $this->seen());
    }

    public function testUserStoreAnswersComeBackWhole(): void
    {
        $store = [
            'url' => 'https://api.acme.test/touchque/user-store',
            'enabled' => true,
            'active' => true,
            'movedIn' => 12,
            'lastCall' => ['at' => '2026-11-17T08:00:00.000Z', 'event' => 'user_store.verify_password', 'ok' => true, 'status' => 200, 'ms' => 84, 'error' => null],
            'paused' => false,
            'updatedAt' => '2026-11-17T07:00:00.000Z',
            'signing' => 'Signed like Touchque webhooks: HMAC-SHA256 with your API secret (x-signature); check it with your SDK\'s webhook verify.',
        ];
        $tq = $this->server([
            'GET /identity/user-store' => [[200, $store]],
            'PUT /identity/user-store' => [[201, $store], [200, ['enabled' => false, 'active' => false] + $store], [200, $store], [409, ['error' => 'passwords_off', 'field' => 'enabled', 'message' => 'Moving users in checks their passwords: turn passwords on first']]],
        ]);

        $this->assertSame($store, $tq->identity->getUserStore());
        $this->assertSame($store, $tq->identity->setUserStore(['url' => 'https://api.acme.test/touchque/user-store', 'enabled' => true]));
        // Either field may be left out: Touchque keeps the URL set, or turns a new store on.
        $this->assertFalse($tq->identity->setUserStore(['enabled' => false])['active']);
        $tq->identity->setUserStore([]);

        $e = $this->refusal(fn () => $tq->identity->setUserStore(['enabled' => true]));
        $this->assertSame([409, 'passwords_off', 'enabled'], [$e->getStatus(), $e->getData()['error'], $e->getData()['field']]);

        $seen = $this->seen();
        $this->assertSame(['GET /identity/user-store', 'PUT /identity/user-store', 'PUT /identity/user-store', 'PUT /identity/user-store', 'PUT /identity/user-store'], array_column($seen, 'call'));
        $this->assertSame('', $seen[0]['body']);
        $this->assertSame(['url' => 'https://api.acme.test/touchque/user-store', 'enabled' => true], json_decode($seen[1]['body'], true));
        $this->assertSame('{"enabled":false}', $seen[2]['body']);
        $this->assertSame('{}', $seen[3]['body']);
    }

    public function testUserStoreTestSendsTheUrlAsGivenOrNoneForTheEndpointSet(): void
    {
        $tq = $this->server(['POST /identity/user-store/test' => [
            [200, ['ok' => true, 'error' => null, 'ms' => 42]],
            [200, ['ok' => true, 'error' => null, 'ms' => 40]],
            [200, ['ok' => false, 'error' => 'answered 500', 'ms' => 31]],
            [400, ['error' => 'invalid_request', 'field' => 'url', 'message' => 'url is required']],
        ]]);

        // null and '': the endpoint set (no url in the body, an empty JSON object).
        $this->assertSame(['ok' => true, 'error' => null, 'ms' => 42], $tq->identity->testUserStore());
        $this->assertSame(['ok' => true, 'error' => null, 'ms' => 40], $tq->identity->testUserStore(''));
        // Any other string is sent as given; a ping that fails is an answer, not an exception.
        $this->assertSame(['ok' => false, 'error' => 'answered 500', 'ms' => 31], $tq->identity->testUserStore('https://staging.acme.test/touchque/user-store?v=2&q=café'));
        // None given and none set: Touchque refuses it (400 invalid_request, field url).
        $e = $this->refusal(fn () => $tq->identity->testUserStore(null));
        $this->assertSame([400, 'invalid_request', 'url'], [$e->getStatus(), $e->getData()['error'], $e->getData()['field']]);

        $seen = $this->seen();
        $this->assertSame(['{}', '{}'], [$seen[0]['body'], $seen[1]['body']]);
        $this->assertSame(['url' => 'https://staging.acme.test/touchque/user-store?v=2&q=café'], json_decode($seen[2]['body'], true));
        $this->assertSame('{}', $seen[3]['body']);
    }

    public function testRemovingTheUserStoreIsIdempotentAndA404IsNotSwallowed(): void
    {
        $tq = $this->server(['DELETE /identity/user-store' => [
            [204, null],
            [204, null],
            [404, ['error' => 'not_enabled', 'message' => 'PUT /identity/tenant first']],
        ]]);

        $this->assertSame([], $tq->identity->removeUserStore());
        $this->assertSame([], $tq->identity->removeUserStore()); // nothing set: still 204
        // 404 is Touchque Login not set up for the workspace, never "no store".
        $e = $this->refusal(fn () => $tq->identity->removeUserStore());
        $this->assertSame([404, 'not_enabled'], [$e->getStatus(), $e->getData()['error']]);
        $this->assertSame(['', '', ''], array_column($this->seen(), 'body'));
    }

    public function testCustomDomains(): void
    {
        $domains = [
            ['id' => 'dom_1', 'domain' => 'login.acme.com', 'status' => 'verified', 'primary' => true, 'dns' => ['points' => 'here', 'cloudflareProxy' => false, 'caaBlocks' => false, 'problems' => []], 'autoCheckUntil' => '2026-11-20T08:00:00.000Z'],
            ['id' => 'dom 2', 'domain' => 'id.acme.com', 'status' => 'pending', 'primary' => false, 'dns' => null, 'autoCheckUntil' => '2026-11-20T09:00:00.000Z'],
        ];
        $tq = $this->server([
            'GET /identity/custom-domains' => [
                [200, ['domains' => $domains, 'verifiedDomains' => ['acme.com'], 'slugPasskeys' => 3]],
                [200, ['domains' => $domains, 'verifiedDomains' => ['acme.com'], 'slugPasskeys' => 3]],
                [200, ['domains' => $domains, 'verifiedDomains' => ['acme.com'], 'slugPasskeys' => 3]],
                [200, ['domains' => $domains, 'verifiedDomains' => ['acme.com'], 'slugPasskeys' => 3]],
                // The organization's domains could not be read: verifiedDomains null.
                [200, ['domains' => [], 'verifiedDomains' => null, 'slugPasskeys' => 0]],
                // An answer without the two fields still has the three keys.
                [200, ['domains' => $domains]],
            ],
            'POST /identity/custom-domains/dom%2F3%20%C3%A9/verify' => [[200, ['id' => 'dom/3 é', 'status' => 'verified', 'proof' => 'txt']]],
        ]);

        $this->assertSame(['domains' => $domains, 'verifiedDomains' => ['acme.com'], 'slugPasskeys' => 3], $tq->identity->customDomains->overview());
        $this->assertSame($domains, $tq->identity->customDomains->list());
        // No read by id in the API: get() finds the domain in the list.
        $this->assertSame($domains[1], $tq->identity->customDomains->get('dom 2'));
        // An unknown id throws what the API answers for one: 404 not_found.
        $e = $this->refusal(fn () => $tq->identity->customDomains->get('dom_9'));
        $this->assertSame([404, 'not_found', 'not_found'], [$e->getStatus(), $e->getMessage(), $e->getData()['error']]);
        $this->assertIsString($e->getData()['message']);
        $this->assertSame(['domains' => [], 'verifiedDomains' => null, 'slugPasskeys' => 0], $tq->identity->customDomains->overview());
        $this->assertSame(['domains' => $domains, 'verifiedDomains' => null, 'slugPasskeys' => 0], $tq->identity->customDomains->overview());
        // verify() posts {} to the id's path, encoded, and answers the domain.
        $this->assertSame(['id' => 'dom/3 é', 'status' => 'verified', 'proof' => 'txt'], $tq->identity->customDomains->verify('dom/3 é'));

        $seen = $this->seen();
        $this->assertSame(array_fill(0, 6, 'GET /identity/custom-domains'), array_column(array_slice($seen, 0, 6), 'call'));
        $this->assertSame(['call' => 'POST /identity/custom-domains/dom%2F3%20%C3%A9/verify', 'body' => '{}'], $seen[6]);
    }

    /**
     * A user store request exactly as Touchque builds it (as the API server does, in Node) passes
     * $tq->webhook->verify() with the x-signature header, and a second delivery of its jti is a replay.
     */
    public function testAUserStoreRequestPassesWebhookVerify(): void
    {
        exec('which node', $out, $code);
        if ($code !== 0) {
            $this->markTestSkipped('node is required to sign like Touchque');
        }
        $js = <<<'JS'
const crypto = require('crypto');
const input = JSON.parse(process.argv[process.argv.length - 1]);
const payload = { event: input.event, tenant: 'acme', ...input.fields, timestamp: new Date().toISOString(), jti: crypto.randomUUID() };
const canonical = JSON.stringify(Object.keys(payload).sort().reduce((acc, k) => ((acc[k] = payload[k]), acc), {}));
const signature = crypto.createHmac('sha256', String(input.secret)).update(canonical).digest('hex');
process.stdout.write(JSON.stringify({ raw: JSON.stringify({ ...payload, signature }), signature }));
JS;
        // $fields is JSON text, so a test can give Node a string PHP cannot hold (an unpaired surrogate).
        $sign = static function (string $event, string $fields) use ($js): array {
            $input = '{"event":' . json_encode($event) . ',"fields":' . $fields . ',"secret":"test_secret"}';
            $process = proc_open(['node', '-e', $js, $input], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $out = (string)stream_get_contents($pipes[1]);
            proc_close($process);
            return json_decode($out, true);
        };
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        $cache = new MemoryReplayCache();

        $password = "pässwörd 🔑 \"café\" / \\ <b>& \u{2028}\u{2029} \x00\x01";
        $request = $sign('user_store.verify_password', (string)json_encode(['email' => 'ada@acme.com', 'password' => $password]));
        $call = $tq->webhook->verify($request['raw'], $request['signature'], 300, $cache);
        $this->assertSame(['user_store.verify_password', 'acme', 'ada@acme.com', $password], [$call['event'], $call['tenant'], $call['email'], $call['password']]);

        $this->assertSame('ada@acme.com', $tq->webhook->verify(...array_values($sign('user_store.get_user', '{"email":"ada@acme.com"}')))['email']);
        $this->assertSame('user_store.ping', $tq->webhook->verify(...array_values($sign('user_store.ping', '{}')))['event']);

        // A password posted as JSON may hold an unpaired surrogate; Touchque writes it as \ud800.
        $lone = $sign('user_store.verify_password', '{"email":"ada@acme.com","password":"a\\ud800b\\udfff"}');
        $this->assertStringContainsString('"password":"a\\ud800b\\udfff"', $lone['raw']);
        $this->assertSame("a\u{FFFD}b\u{FFFD}", $tq->webhook->verify($lone['raw'], $lone['signature'], 300, $cache)['password']);

        $this->expectException(TouchqueWebhookReplayException::class);
        $tq->webhook->verify($request['raw'], $request['signature'], 300, $cache);
    }
}
