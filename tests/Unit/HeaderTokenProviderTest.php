<?php

use Illuminate\Http\Request;
use SPie\LaravelJWT\TokenProvider\HeaderTokenProvider;

/**
 * Class HeaderTokenProviderTest
 */
class HeaderTokenProviderTest extends TestCase
{

    use HttpHelper;

    //region Tests

    /**
     * @return void
     */
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

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertEmpty(
            $this->createHeaderTokenProvider($this->getFaker()->uuid)->getRequestToken($this->createEmptyRequest())
        );
    }

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutMatch(): void
    {
        $headerName = $this->getFaker()->uuid;

        $this->assertEmpty(
            $this->createHeaderTokenProvider($headerName)
                 ->getRequestToken($this->createRequestWithHeader($headerName, $this->getFaker()->uuid))
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
            'Bearer ' . $token,
            $this->createHeaderTokenProvider($headerName)
                ->setResponseToken($this->createEmptyResponse(), $token)->headers->get($headerName)
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

    /**
     * @param string $headerName
     * @param string $value
     *
     * @return Request
     */
    private function createRequestWithHeader(string $headerName, string $value): Request
    {
        $request = $this->createEmptyRequest();
        $request->headers->set($headerName, $value);

        return $request;
    }
}
