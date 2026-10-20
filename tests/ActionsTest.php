<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\TouchQue;

/**
 * TouchQue Actions in the PHP SDK: every management call sends exactly what
 * the shared vectors (fixtures/actions-api-vectors.json) say, against the
 * shared fake TouchQue API, signed like the real API.
 */
class ActionsTest extends TestCase
{
    private static FakeApi $api;
    private static array $vectors;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
        self::$vectors = json_decode((string)file_get_contents(__DIR__ . '/../fixtures/actions-api-vectors.json'), true);
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    private function client(): TouchQue
    {
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    private function call(TouchQue $tq, string $name, array $a)
    {
        $acts = $tq->actions;
        switch ($name) {
            case 'deploy': return $acts->deploy($a['slug'], ['trigger' => $a['trigger'], 'code' => $a['code'], 'secrets' => $a['secrets'], 'name' => $a['name']]);
            case 'deployTemplate': return $acts->deploy($a['slug'], ['trigger' => $a['trigger'], 'template' => $a['template'], 'onFailure' => $a['onFailure']]);
            case 'deployLoosening': return $acts->deploy($a['slug'], ['trigger' => $a['trigger'], 'code' => $a['code'], 'capabilities' => $a['capabilities'], 'allowedHosts' => $a['allowedHosts']]);
            case 'list': return $acts->list();
            case 'get': return $acts->get($a['slug']);
            case 'version': return $acts->version($a['slug'], $a['number']);
            case 'update': return $acts->update($a['slug'], ['enabled' => $a['enabled']]);
            case 'rollback': return $acts->rollback($a['slug'], $a['version']);
            case 'rollbackPrevious': return $acts->rollback($a['slug']);
            case 'test': return $acts->test(['trigger' => $a['trigger'], 'code' => $a['code'], 'eventId' => $a['eventId']]);
            case 'testDeployed': return $acts->test(['slug' => $a['slug'], 'event' => $a['event']]);
            case 'dryRun': return $acts->dryRun(['trigger' => $a['trigger'], 'code' => $a['code'], 'replaces' => $a['replaces'], 'limit' => $a['limit']]);
            case 'events': return $acts->events(['trigger' => $a['trigger'], 'limit' => $a['limit']]);
            case 'logs': return $acts->logs($a['slug'], ['limit' => $a['limit']]);
            case 'metrics': return $acts->metrics($a['slug'], $a['window']);
            case 'triggers': return $acts->triggers();
            case 'templates': return $acts->templates();
            case 'renderTemplate': return $acts->renderTemplate($a['id'], $a['trigger'], $a['params']);
            case 'setSecret': return $acts->secrets->set($a['name'], $a['value']);
            case 'listSecrets': return $acts->secrets->list();
            case 'deleteSecret': return $acts->secrets->delete($a['name']);
            case 'delete': return $acts->delete($a['slug']);
        }
        throw new \LogicException("no mapping for $name");
    }

    public function testActionsApiVectors(): void
    {
        $tq = $this->client();
        foreach (self::$vectors['calls'] as $v) {
            $result = $this->call($tq, $v['name'], $v['args']);
            $calls = self::$api->calls();
            $last = end($calls);
            $this->assertSame($v['request']['method'], $last['method'], $v['name']);
            $this->assertSame($v['request']['path'], $last['path'], $v['name']);
            parse_str((string)parse_url($last['url'], PHP_URL_QUERY), $query);
            $this->assertEquals($v['request']['query'] ?? [], $query, $v['name']);
            if (!in_array($v['request']['method'], ['GET', 'DELETE'], true)) {
                $this->assertEquals($v['request']['body'] ?? [], $last['body'], $v['name']);
            }
            foreach ($v['expect'] ?? [] as $path => $want) {
                $got = $result;
                foreach (explode('.', $path) as $k) {
                    $got = is_array($got) ? ($got[$k] ?? null) : null;
                }
                $this->assertSame($want, $got, "{$v['name']} $path");
            }
        }
    }

    public function testContextIsPassedThrough(): void
    {
        $tq = $this->client();
        self::$api->link('ctx@example.com');
        $tq->login->request('ctx@example.com', 'LOGIN', null, null, null, false, false, null, null, ['roles' => ['admin'], 'amount' => 2500]);
        $calls = self::$api->calls();
        $this->assertEquals(self::$vectors['context']['loginRequest']['body'], end($calls)['body']);
        $tq->risk->check(['externalUsername' => 'ctx@example.com', 'type' => 'LOGIN', 'context' => ['roles' => ['admin']]]);
        $calls = self::$api->calls();
        $this->assertEquals(self::$vectors['context']['riskCheck']['body'], end($calls)['body']);
    }

    public function testLooseningVersionWaitsForThePhone(): void
    {
        $tq = $this->client();
        $res = $tq->actions->deploy('silent-office', ['trigger' => 'risk.check', 'code' => 'exports.onExecute = (e, api) => api.allowSilent("office");', 'capabilities' => ['allow_silent']]);
        $this->assertFalse($res['deployed']);
        $this->assertTrue($res['approval']['required']);
        self::$api->approveVersion('silent-office', 1);
        $this->assertSame(1, $tq->actions->get('silent-office')['action']['activeVersion']);
    }

    public function testBadInputIsRefusedBeforeAnyRequest(): void
    {
        $tq = $this->client();
        foreach ([
            fn () => $tq->actions->deploy('Bad Slug', ['trigger' => 'login.request', 'code' => 'x']),
            fn () => $tq->actions->deploy('no-code', ['trigger' => 'login.request']),
            fn () => $tq->actions->deploy('typo', ['trigger' => 'login.request', 'code' => 'x', 'onFaliure' => 'deny']),
            fn () => $tq->actions->secrets->set('lowercase', 'v'),
        ] as $i => $fn) {
            try {
                $fn();
                $this->fail("case $i did not throw");
            } catch (TouchQueConfigException $e) {
                $this->assertNotSame('', $e->getMessage());
            }
        }
    }

    public function testActionTypesMoved(): void
    {
        $tq = $this->client();
        $tq->actionTypes->define('EXPORT_DATA', 'Export data', null, true);
        $calls = self::$api->calls();
        $last = end($calls);
        $this->assertSame(['POST', '/action-types', ['type' => 'EXPORT_DATA', 'name' => 'Export data', 'critical' => true]], [$last['method'], $last['path'], $last['body']]);
    }
}
