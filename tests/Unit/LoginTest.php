<?php

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Events\Login;

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

        $loginEvent = new Login($user, $accessToken);

        $this->assertEquals($user, $loginEvent->getUser());
        $this->assertEquals($accessToken, $loginEvent->getAccessToken());
    }
}