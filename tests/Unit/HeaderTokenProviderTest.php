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
        $prefix = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;
        $request = new Request();
        $request->headers->set($headerName, $prefix . ' ' . $token);

        $this->assertEquals($token, $this->createHeaderTokenProvider($headerName, $prefix)->getRequestToken($request));
    }

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutPrefix(): void
    {
        $headerName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;
        $request = new Request();
        $request->headers->set($headerName, $token);

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
        $request->headers->set($headerName, $this->getFaker()->uuid . ' ' . $this->getFaker()->uuid);

        $this->assertEmpty(
            $this->createHeaderTokenProvider($headerName, $this->getFaker()->uuid)->getRequestToken($request)
        );
    }

    /**
     * @return void
     */
    public function testSetResponseToken(): void
    {
        $token = $this->getFaker()->uuid;
        $headerName = $this->getFaker()->uuid;
        $prefix = $this->getFaker()->uuid;

        $this->assertEquals(
            $prefix . ' ' . $token,
            $this->createHeaderTokenProvider($headerName, $prefix)
                ->setResponseToken(new Response(), $token)->headers->get($headerName)
        );
    }

    /**
     * @return void
     */
    public function testSetResponseTokenWithoutPrefix(): void
    {
        $token = $this->getFaker()->uuid;
        $headerName = $this->getFaker()->uuid;

        $this->assertEquals(
            $token,
            $this->createHeaderTokenProvider($headerName)
                ->setResponseToken(new Response(), $token)->headers->get($headerName)
        );
    }

    //endregion

    /**
     * @param string      $headerName
     * @param string|null $prefix
     *
     * @return HeaderTokenProvider
     */
    private function createHeaderTokenProvider(string $headerName, string $prefix = null): HeaderTokenProvider
    {
        return new HeaderTokenProvider($headerName, $prefix);
    }
}