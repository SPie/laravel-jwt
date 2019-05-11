<?php

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Events\RefreshAccessToken;

/**
 * Class RefreshAccessTokenTest
 */
class RefreshAccessTokenTest extends TestCase
{

    use TestHelper;

    /**
     * @return void
     */
    public function testConstruct(): void
    {
        $user = Mockery::mock(JWTAuthenticatable::class);
        $accessToken = Mockery::mock(JWT::class);
        $refreshToken = Mockery::mock(JWT::class);

        $refreshAccessTokenEvent = new RefreshAccessToken($user, $accessToken, $refreshToken);

        $this->assertEquals($user, $refreshAccessTokenEvent->getUser());
        $this->assertEquals($accessToken, $refreshAccessTokenEvent->getAccessToken());
        $this->assertEquals($refreshToken, $refreshAccessTokenEvent->getRefreshToken());
    }
}
