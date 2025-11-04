<?php

namespace SPie\LaravelJWT\Test\Unit\TokenProvider;

use Illuminate\Contracts\Cookie\Factory;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Mockery as m;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\TestHelper;
use SPie\LaravelJWT\TokenProvider\CookieTokenProvider;
use Symfony\Component\HttpFoundation\Cookie;

final class CookieTokenProviderTest extends TestCase
{
    use TestHelper;
    use HttpHelper;

    private function createCookieTokenProvider(?string $cookieName = null, ?Factory  $cookieFactory = null): CookieTokenProvider
    {
        return (new CookieTokenProvider(
            $cookieFactory ?: $this->createCookieFactory()
        ))->setKey($cookieName ?: $this->getFaker()->word);
    }

    private function createRequestWithCookie(string $cookieName, string $token): Request
    {
        $request = $this->createEmptyRequest();
        $request->cookies->set($cookieName, $token);

        return $request;
    }

    /**
     * @return Factory|MockInterface
     */
    private function createCookieFactory(): Factory
    {
        return m::spy(Factory::class);
    }

    private function mockCookieFactoryMake(MockInterface $cookieFactory, Cookie $cookie, string $name, string $value): self
    {
        $cookieFactory
            ->shouldReceive('make')
            ->with($name, $value)
            ->andReturn($cookie);

        return $this;
    }

    /**
     * @return Cookie|MockInterface
     */
    private function createCookie(): Cookie
    {
        return m::spy(Cookie::class);
    }

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

    public function testGetRequestTokenWithoutToken(): void
    {
        $this->assertEmpty(
            $this->createCookieTokenProvider($this->getFaker()->uuid)->getRequestToken($this->createEmptyRequest())
        );
    }

    public function testSetResponseToken(): void
    {
        $cookieName = $this->getFaker()->uuid;
        $token = $this->getFaker()->uuid;
        $cookie = $this->createCookie();
        $cookieFactory = $this->createCookieFactory();
        $this->mockCookieFactoryMake($cookieFactory, $cookie, $cookieName, $token);

        $this->assertEquals(
            $cookie,
            (new Collection(
                $this->createCookieTokenProvider($cookieName, $cookieFactory)
                    ->setResponseToken($this->createEmptyResponse(), $token)
                    ->headers->getCookies()
            ))->first()
        );
    }
}
