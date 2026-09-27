<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueConfigException;

class ConfigTest extends TestCase
{
    public function testValidConfigIsAccepted(): void
    {
        $config = new Config('tq_auth_test123', 'shh');
        $this->assertSame('tq_auth_test123', $config->getApiKey());
        $this->assertSame('https://api.touchque.com', $config->getBaseUrl());
        $this->assertSame(10000, $config->getTimeout());
    }

    public function testApiKeyNotStartingWithTqThrows(): void
    {
        $this->expectException(TouchQueConfigException::class);
        new Config('wrong_prefix', 'shh');
    }

    public function testCustomBaseUrlTrailingSlashIsStripped(): void
    {
        $config = new Config('tq_auth_x', 'shh', 'http://localhost:9999/', 5000);
        $this->assertSame('http://localhost:9999', $config->getBaseUrl());
        $this->assertSame(5000, $config->getTimeout());
    }

    public function testRefusesPlaintextHttpToNonLocalhostHost(): void
    {
        $this->expectException(TouchQueConfigException::class);
        new Config('tq_auth_x', 'shh', 'http://api.example.com');
    }

    public function testAllowsPlaintextHttpForLoopbackAndHttpsElsewhere(): void
    {
        $this->assertSame('http://127.0.0.1:9999', (new Config('tq_auth_x', 'shh', 'http://127.0.0.1:9999'))->getBaseUrl());
        $this->assertSame('https://api.example.com', (new Config('tq_auth_x', 'shh', 'https://api.example.com'))->getBaseUrl());
    }
    public function testReadsFromEnvironmentWhenArgumentsOmitted(): void
    {
        putenv('TQ_API_KEY=tq_env_key');
        putenv('TQ_API_SECRET=env_secret');
        putenv('TQ_API_URL=https://custom.example.com');
        try {
            $config = new Config();
            $this->assertSame('tq_env_key', $config->getApiKey());
            $this->assertSame('env_secret', $config->getApiSecret());
            $this->assertSame('https://custom.example.com', $config->getBaseUrl());
        } finally {
            putenv('TQ_API_KEY');
            putenv('TQ_API_SECRET');
            putenv('TQ_API_URL');
        }
    }

    public function testMissingCredentialsThrowClearError(): void
    {
        putenv('TQ_API_KEY');
        putenv('TQ_API_SECRET');
        $this->expectException(TouchQueConfigException::class);
        new Config();
    }
}
