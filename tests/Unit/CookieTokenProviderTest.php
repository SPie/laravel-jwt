<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\TestHelper;
use SPie\LaravelJWT\TokenProvider\CookieTokenProvider;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Class CookieTokenProviderTest
 */
final class CookieTokenProviderTest extends TestCase
{
    use TestHelper;
    use HttpHelper;

    //region Tests

    /**
     * @return void
     */
    public function testGetRequestToken(): void
    {
        $cookieName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;

        $this->assertEquals(
            $token,
            $this->createCookieTokenProvider($cookieName)
                 ->getRequestToken($this->createRequestWithCookie($cookieName, $token))
        );
    }

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertEmpty(
            $this->createCookieTokenProvider($this->getFaker()->uuid)->getRequestToken($this->createEmptyRequest())
        );
    }

    /**
     * @return void
     */
    public function testSetResponseToken(): void
    {
        $cookieName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;

        $this->assertEquals(
            $token,
            (new Collection(
                $this->createCookieTokenProvider($cookieName)
                    ->setResponseToken($this->createEmptyResponse(), $token)
                    ->headers->getCookies())
            )
                ->first(function (Cookie $cookie) use ($cookieName) {
                    return ($cookie->getName() == $cookieName);
                })
                ->getValue()
        );
    }

    //endregion

    /**
     * @param string $cookieName
     *
     * @return CookieTokenProvider
     */
    private function createCookieTokenProvider(string $cookieName): CookieTokenProvider
    {
        return (new CookieTokenProvider())->setKey($cookieName);
    }

    /**
     * @param string $cookieName
     * @param string $token
     *
     * @return Request
     */
    private function createRequestWithCookie(string $cookieName, string $token): Request
    {
        $request = $this->createEmptyRequest();
        $request->cookies->set($cookieName, $token);

        return $request;
    }
}
