<?php

namespace SPie\LaravelJWT\Test\Unit;

use Mockery;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Events\Login;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class LoginTest
 */
final class LoginTest extends TestCase
{
    use TestHelper;

    /**
     * @return void
     */
    public function testConstruct(): void
    {
        $user = Mockery::mock(JWTAuthenticatable::class);
        $accessToken = Mockery::mock(JWT::class);
        $ipAddress = $this->getFaker()->ipv4;

        $loginEvent = new Login($user, $accessToken, $ipAddress);

        $this->assertEquals($user, $loginEvent->getUser());
        $this->assertEquals($accessToken, $loginEvent->getAccessToken());
        $this->assertEquals($ipAddress, $loginEvent->getIpAddress());
    }

    /**
     * @return void
     */
    public function testConstructWithoutOptionalParameters(): void
    {
        $user = Mockery::mock(JWTAuthenticatable::class);
        $accessToken = Mockery::mock(JWT::class);

        $loginEvent = new Login($user, $accessToken);

        $this->assertEquals($user, $loginEvent->getUser());
        $this->assertEquals($accessToken, $loginEvent->getAccessToken());
        $this->assertEquals(null, $loginEvent->getIpAddress());
    }
}
