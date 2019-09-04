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
        $credentials = [$this->getFaker()->uuid => $this->getFaker()->uuid];

        $loginEvent = new Login($user, $accessToken, $credentials);

        $this->assertEquals($user, $loginEvent->getUser());
        $this->assertEquals($accessToken, $loginEvent->getAccessToken());
        $this->assertEquals($credentials, $loginEvent->getCredentials());
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
        $this->assertEquals([], $loginEvent->getCredentials());
    }
}
