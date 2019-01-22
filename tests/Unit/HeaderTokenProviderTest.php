<?php

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use SPie\LaravelJWT\TokenProvider\HeaderTokenProvider;

/**
 * Class HeaderTokenProviderTest
 */
class HeaderTokenProviderTest extends TestCase
{

    //region Tests

    /**
     * @return void
     */
    public function testGetRequestToken(): void
    {
        $headerName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;
        $request = new Request();
        $request->headers->set($headerName, HeaderTokenProvider::BEARER_PREFIX . ' ' . $token);

        $this->assertEquals($token, $this->createHeaderTokenProvider($headerName)->getRequestToken($request));
    }

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertEmpty($this->createHeaderTokenProvider($this->getFaker()->uuid)->getRequestToken(new Request()));
    }

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutMatch(): void
    {
        $headerName = $this->getFaker()->uuid;
        $request = new Request();
        $request->headers->set($headerName, $this->getFaker()->uuid);

        $this->assertEmpty(
            $this->createHeaderTokenProvider($headerName)->getRequestToken($request)
        );
    }

    /**
     * @return void
     */
    public function testSetResponseToken(): void
    {
        $token = $this->getFaker()->uuid;
        $headerName = $this->getFaker()->uuid;

        $this->assertEquals(
            HeaderTokenProvider::BEARER_PREFIX . ' ' . $token,
            $this->createHeaderTokenProvider($headerName)
                ->setResponseToken(new Response(), $token)->headers->get($headerName)
        );
    }

    //endregion

    /**
     * @param string $headerName
     *
     * @return HeaderTokenProvider
     */
    private function createHeaderTokenProvider(string $headerName): HeaderTokenProvider
    {
        return (new HeaderTokenProvider())->setKey($headerName);
    }
}
