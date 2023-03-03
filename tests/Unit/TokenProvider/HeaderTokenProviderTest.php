<?php

namespace SPie\LaravelJWT\Test\Unit\TokenProvider;

use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\TestHelper;
use SPie\LaravelJWT\TokenProvider\HeaderTokenProvider;

final class HeaderTokenProviderTest extends TestCase
{
    use TestHelper;
    use HttpHelper;

    private function createHeaderTokenProvider(string $headerName): HeaderTokenProvider
    {
        return (new HeaderTokenProvider())->setKey($headerName);
    }

    private function createRequestWithHeader(string $headerName, string $value): Request
    {
        $request = $this->createEmptyRequest();
        $request->headers->set($headerName, $value);

        return $request;
    }

    public function testGetRequestToken(): void
    {
        $headerName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;

        $this->assertEquals(
            $token,
            $this->createHeaderTokenProvider($headerName)
                 ->getRequestToken($this->createRequestWithHeader($headerName, 'Bearer ' . $token))
        );
    }

    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertEmpty(
            $this->createHeaderTokenProvider($this->getFaker()->uuid)->getRequestToken($this->createEmptyRequest())
        );
    }

    public function testGetRequestTokenWithoutMatch(): void
    {
        $headerName = $this->getFaker()->uuid;

        $this->assertEmpty(
            $this->createHeaderTokenProvider($headerName)
                 ->getRequestToken($this->createRequestWithHeader($headerName, $this->getFaker()->uuid))
        );
    }

    public function testSetResponseToken(): void
    {
        $token = $this->getFaker()->uuid;
        $headerName = $this->getFaker()->uuid;

        $this->assertEquals(
            'Bearer ' . $token,
            $this->createHeaderTokenProvider($headerName)
                ->setResponseToken($this->createEmptyResponse(), $token)->headers->get($headerName)
        );
    }
}
