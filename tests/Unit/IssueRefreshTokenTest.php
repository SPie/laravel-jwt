<?php

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Events\IssueRefreshToken;

/**
 * Class IssueRefreshTokenTest
 */
class IssueRefreshTokenTest extends TestCase
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

        $issueRefreshTokenEvent = new IssueRefreshToken($user, $accessToken, $refreshToken);

        $this->assertEquals($user, $issueRefreshTokenEvent->getUser());
        $this->assertEquals($accessToken, $issueRefreshTokenEvent->getAccessToken());
        $this->assertEquals($refreshToken, $issueRefreshTokenEvent->getRefreshToken());
    }
}

