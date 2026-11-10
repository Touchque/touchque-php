<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\CodeReply;
use TouchQue\Config;
use TouchQue\TouchQue;

/**
 * A code typed back on the phone against the shared fake TouchQue API, which seals it like the
 * phone does: it opens only with the one-time key, for that request.
 */
final class CodeReplyTest extends TestCase
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

    public function testTheTypedCodeOpensOnlyWithTheOneTimeKeyForThatRequest(): void
    {
        self::$api->link('ayse@acme.com');
        $tq = new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
        $key = CodeReply::newKey();
        $sent = $tq->login->request('ayse@acme.com', reply: ['kind' => 'code', 'key' => $key['publicKey'], 'channel' => 'sms', 'target' => '+**********26']);
        $this->assertArrayNotHasKey('reply', $tq->login->status($sent['requestId']));
        self::$api->post('/__test/approve', ['id' => $sent['requestId'], 'replyCode' => '482 913']);
        $ct = $tq->login->status($sent['requestId'])['reply']['ct'];
        $this->assertSame('482 913', CodeReply::open($key['privateKey'], $sent['requestId'], $ct));
        $this->assertNull(CodeReply::open($key['privateKey'], 'another-request', $ct));
        $this->assertNull(CodeReply::open(CodeReply::newKey()['privateKey'], $sent['requestId'], $ct));
        $this->assertNull(CodeReply::open($key['privateKey'], $sent['requestId'], 'v1.bad.ct'));
    }

    public function testAKeyExportedInTheSec1FormOfPhpBefore81IsKeptAsPkcs8(): void
    {
        // PHP 7.4 and 8.0 export an EC key as `EC PRIVATE KEY` (SEC1); build that form by hand.
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $ec = openssl_pkey_get_details($key)['ec'];
        $pad = static fn (string $v) => str_pad($v, 32, "\0", STR_PAD_LEFT);
        $sec1 = hex2bin('307702010104') . "\x20" . $pad($ec['d']) . hex2bin('a00a06082a8648ce3d030107a144034200')
            . "\x04" . $pad($ec['x']) . $pad($ec['y']);
        $pem = "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($sec1), 64, "\n") . "-----END EC PRIVATE KEY-----\n";

        $method = new \ReflectionMethod(CodeReply::class, 'pkcs8');
        if (\PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }
        $der = $method->invoke(null, $pem);

        $loaded = openssl_pkey_get_private("-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PRIVATE KEY-----\n");
        $this->assertNotFalse($loaded, 'the key must load as PKCS#8, which open() reads');
        $this->assertSame(bin2hex($pad($ec['d'])), bin2hex($pad(openssl_pkey_get_details($loaded)['ec']['d'])));
    }
}
