<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\TestHelper;
use SPie\LaravelJWT\TokenProvider\JsonTokenProvider;

final class JsonTokenProviderTest extends TestCase
{
    use HttpHelper;
    use TestHelper;

    private function getJsonTokenProvider(string $key = null): JsonTokenProvider
    {
        return (new JsonTokenProvider())->setKey($key ?: $this->getFaker()->word);
    }

    private function createRequestWithToken(string $key, string $token): Request
    {
        $request = $this->createEmptyRequest();
        $request->initialize([$key => $token]);

        return $request;
    }

    public function testGetRequestToken(): void
    {
        $key = $this->getFaker()->word;
        $token = $this->getFaker()->word;
        $request = $this->createRequestWithToken($key, $token);

        $this->assertEquals($token, $this->getJsonTokenProvider($key)->getRequestToken($request));
    }

    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertNull($this->getJsonTokenProvider()->getRequestToken($this->createEmptyRequest()));
    }

    public function testSetResponseTokenForJsonResponse(): void
    {
        $key = $this->getFaker()->uuid;
        $token = $this->getFaker()->word;
        $content = [$this->getFaker()->uuid => $this->getFaker()->word];
        $response = $this->createEmptyResponse()->setContent($content);

        $response = $this->getJsonTokenProvider($key)->setResponseToken($response, $token);

        $this->assertEquals(\array_merge($content, [$key => $token]), \json_decode($response->getContent(), true));
    }

    public function testSetResponseTokenWithoutJsonResponse(): void
    {
        $key = $this->getFaker()->uuid;
        $token = $this->getFaker()->word;
        $content = $this->getFaker()->word;
        $response = $this->createEmptyResponse()->setContent($content);

        $response = $this->getJsonTokenProvider($key)->setResponseToken($response, $token);

        $this->assertEquals($content, $response->getContent());
    }
}
