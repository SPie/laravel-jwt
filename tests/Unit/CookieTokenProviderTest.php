<?php

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Collection;
use SPie\LaravelJWT\TokenProvider\CookieTokenProvider;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Class CookieTokenProviderTest
 */
class CookieTokenProviderTest extends TestCase {

    //region Tests

    /**
     * @return void
     */
    public function testGetRequestToken(): void
    {
        $cookieName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;
        $request = new Request();
        $request->cookies->set($cookieName, $token);

        $this->assertEquals($token, $this->createCookieTokenProvider($cookieName)->getRequestToken($request));
    }

    /**
     * @return void
     */
    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertEmpty(
            $this->createCookieTokenProvider($this->getFaker()->uuid)->getRequestToken(new Request())
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
                    ->setResponseToken(new Response(), $token)
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
        return new CookieTokenProvider($cookieName);
    }
}