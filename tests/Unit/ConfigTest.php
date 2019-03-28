<?php

class ConfigTest extends TestCase
{

    public function testConfigFileKeys(): void
    {
        $config = include __DIR__ . '/../../config/jwt.php';

        $this->assertArrayHasKey('secret', $config);
        $this->assertArrayHasKey('issuer', $config);
        $this->assertArrayHasKey('signer', $config);
        $this->assertArrayHasKey('accessTokenProvider', $config);
        $this->assertArrayHasKey('class', $config['accessTokenProvider']);
        $this->assertArrayHasKey('key', $config['accessTokenProvider']);
        $this->assertArrayHasKey('ttl', $config['accessTokenProvider']);
        $this->assertArrayHasKey('tokenBlacklist', $config);
        $this->assertArrayHasKey('refreshTokenProvider', $config);
        $this->assertArrayHasKey('class', $config['refreshTokenProvider']);
        $this->assertArrayHasKey('key', $config['refreshTokenProvider']);
        $this->assertArrayHasKey('ttl', $config['refreshTokenProvider']);
        $this->assertArrayHasKey('refreshTokenRepository', $config);
    }
}
