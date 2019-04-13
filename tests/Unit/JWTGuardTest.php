<?php

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\MissingRefreshTokenProviderException;
use SPie\LaravelJWT\Exceptions\MissingRefreshTokenRepositoryException;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class JWTGuardTest
 */
final class JWTGuardTest extends TestCase
{

    use TestHelper;
    use JWTHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testUserWithValidToken(): void
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $jwt = $this->createJWT();
        $this->addGetValidJWT(
            $jwtHandler,
            $jwt
        );

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            new Request(),
            $this->createAccessTokenProvider($this->getFaker()->uuid)
        );

        $this->assertEquals($user, $jwtGuard->user());
        $jwtGuard
            ->shouldHaveReceived('setUser')
            ->with($user)
            ->once();
        $jwtGuard
            ->shouldHaveReceived('setAccessToken')
            ->with($jwt)
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testUserWithExistingUser(): void
    {
        $user = $this->createUser();
        $jwtGuard = $this->createJWTGuard();
        $jwtGuard->setUser($user);

        $this->assertEquals($user, $jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testUserEmptyToken(): void
    {
        $this->assertEmpty($this->createJWTGuard()->user());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testUserInvalidToken(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, new InvalidTokenException());

        $this->assertEmpty(
            $this->createJWTGuard(
                $jwtHandler,
                null,
                null,
                $this->createAccessTokenProvider($this->getFaker()->uuid)
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testUserWithEmptyBlacklist(): void
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $this->createJWT());
        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, false);

        $this->assertEquals(
            $user,
            $this->createJWTGuard(
                $jwtHandler,
                $this->createUserProvider($user),
                new Request(),
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                null,
                $tokenBlacklist
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testUserWithRevokedToken(): void
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $this->createJWT());
        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, true);

        $this->assertEmpty(
            $this->createJWTGuard(
                $jwtHandler,
                $this->createUserProvider($user),
                new Request(),
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                null,
                $tokenBlacklist
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithoutRevokedRefreshToken(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;
        $user = $this->createUser();
        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($refreshTokenId);
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->andReturn(false);

        $this->assertEquals(
            $user,
            $this->createJWTGuard(
                $jwtHandler,
                $this->createUserProvider($user),
                new Request(),
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                null,
                null,
                null,
                null,
                $refreshTokenRepository
            )->user()
        );

        $refreshTokenRepository
            ->shouldHaveReceived('isRefreshTokenRevoked')
            ->with($refreshTokenId)
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithRevokedRefreshToken(): void
    {
        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->andReturn(true);

        $this->assertEmpty(
            $this->createJWTGuard(
                $jwtHandler,
                $this->createUserProvider($this->createUser()),
                new Request(),
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                null,
                null,
                null,
                null,
                $refreshTokenRepository
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithRefreshToken(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->andReturn(false);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            new Request(),
            null,
            null,
            null,
            $this->createRefreshTokenProvider($this->getFaker()->uuid),
            null,
            $refreshTokenRepository
        );

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($jwt, $jwtGuard->getRefreshToken());
    }

    /**
     * @return void
     */
    public function testUserWithEmptyRefreshToken(): void
    {
        $this->assertEmpty(
            $this->createJWTGuard(
                $this->createJWTHandler(),
                null,
                new Request(),
                null,
                null,
                null,
                $this->createRefreshTokenProvider()
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithInvalidRefreshToken(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, new InvalidSecretException());

        $this->assertEmpty(
            $this->createJWTGuard(
                $jwtHandler,
                null,
                new Request(),
                null,
                null,
                null,
                $this->createRefreshTokenProvider($this->getFaker()->uuid)
            )->user()
        );
    }

    /**
     * @return void
     */
    public function testUserWithRefreshTokenWithoutUser(): void
    {
        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->andReturn(false);

        $this->assertEmpty(
            $this->createJWTGuard(
                $jwtHandler,
                $this->createUserProvider(),
                new Request(),
                null,
                null,
                null,
                $this->createRefreshTokenProvider($this->getFaker()->uuid),
                null,
                $refreshTokenRepository
            )->user()
        );
    }

    /**
     * @return void
     */
    public function testValidate(): void
    {
        $this->assertTrue(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser(), true)
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     */
    public function testValidateWithoutUser(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider()
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     */
    public function testValidateWithInvalidCredentials(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser())
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueAccessTokenWithTTL(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addCreateJWT($jwtHandler, $jwt);
        $accessTokenTTL = $this->getFaker()->numberBetween();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            new Request(),
            null,
            $accessTokenTTL
        );

        $this->assertEquals($jwt, $jwtGuard->issueAccessToken($user));
        $this->assertEquals($jwt, $jwtGuard->getAccessToken());

        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                $user->getAuthIdentifier(),
                $user->getCustomClaims(),
                $accessTokenTTL
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws AuthorizationException
     * @throws Exception
     */
    public function testLogin(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addCreateJWT($jwtHandler, $jwt);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user, true)
        )->login([
            $this->getFaker()->uuid => $this->getFaker()->uuid,
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ]);

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($jwt, $jwtGuard->getAccessToken());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testLoginWithoutUser(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $this->createJWT());

        $jwtGuard = $this->createJWTGuard($jwtHandler, $this->createUserProvider()  );

        try {
            $jwtGuard->login([
                $this->getFaker()->uuid => $this->getFaker()->uuid,
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]);

            $this->assertTrue(false);
        } catch (AuthorizationException $e) {
            $this->assertTrue(true);
        }

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testLoginWithoutJWTAuthenticatable(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $this->createJWT());

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider(
                new class implements Authenticatable {
                    public function getAuthIdentifierName() {}
                    public function getAuthIdentifier() {}
                    public function getAuthPassword() {}
                    public function getRememberToken() {}
                    public function setRememberToken($value) {}
                    public function getRememberTokenName() {}
                }
            )
        );

        try {
            $jwtGuard->login([
                $this->getFaker()->uuid => $this->getFaker()->uuid,
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]);

            $this->assertTrue(false);
        } catch (AuthorizationException $e) {
            $this->assertTrue(true);
        }

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testLoginWithInvalidCredentials(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $this->createJWT());

        $jwtGuard = $this->createJWTGuard($jwtHandler, $this->createUserProvider());

        try {
            $jwtGuard->login([
                $this->getFaker()->uuid => $this->getFaker()->uuid,
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]);

            $this->assertTrue(false);
        } catch (AuthorizationException $e) {
            $this->assertTrue(true);
        }

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testLogout(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $tokenBlacklist = $this->createTokenBlacklist();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            null,
            $tokenBlacklist
        );
        $jwtGuard
            ->shouldReceive('getAccessToken')
            ->andReturn($jwt);
        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->user());
        $tokenBlacklist
            ->shouldHaveReceived('revoke')
            ->with($jwt)
            ->once();
        $jwtGuard
            ->shouldHaveReceived('setAccessToken')
            ->with(null)
            ->once();
        $jwtGuard
            ->shouldHaveReceived('setRefreshToken')
            ->with(null)
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testLogoutWithoutTokenBlacklist(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);

        $jwtGuard = $this->createJWTGuard($jwtHandler);
        $this->addGetAccessToken($jwtGuard, $jwt);
        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->user());
        $jwtGuard
            ->shouldHaveReceived('setAccessToken')
            ->with(null)
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testLogoutWithoutJWT(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $tokenBlacklist = $this->createTokenBlacklist();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            null,
            $tokenBlacklist
        );
        $this->addGetAccessToken($jwtGuard);
        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->user());
        $tokenBlacklist->shouldNotHaveReceived('revoke');
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testLogoutWithRefreshToken(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;

        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($refreshTokenId);
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            null,
            $this->createTokenBlacklist(),
            null,
            null,
            $refreshTokenRepository
        );
        $this->addGetAccessToken($jwtGuard, $jwt);
        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->user());
        $refreshTokenRepository
            ->shouldHaveReceived('revokeRefreshToken')
            ->with($refreshTokenId)
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testLogoutWithoutRefreshToken(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $tokenBlacklist = $this->createTokenBlacklist();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            new Request(),
            $this->createAccessTokenProvider(),
            null,
            $tokenBlacklist,
            null,
            null,
            $refreshTokenRepository
        );
        $this->addGetAccessToken($jwtGuard, $jwt);

        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->user());
        $refreshTokenRepository->shouldNotHaveReceived('revokeRefreshToken');
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshToken(): void
    {
        $user = $this->createUser();
        $refreshToken = $this->createJWT();
        $accessToken = $this->createJWT();
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $accessTokenTTL = $this->getFaker()->numberBetween();
        $refreshTokenIdentifier = $this->getFaker()->uuid;
        $jwtHandler = $this->createJWTHandler();
        $jwtHandler
            ->shouldReceive('createJWT')
            ->andReturn($refreshToken, $accessToken);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            $accessTokenTTL,
            null,
            null,
            null,
            $refreshTokenRepository
        );
        $this
            ->addGetAccessToken($jwtGuard, $this->createJWT())
            ->addCreateRefreshTokenIdentifier($jwtGuard, $refreshTokenIdentifier);
        $jwtGuard->setUser($user);

        $this->assertEquals($refreshToken, $jwtGuard->issueRefreshToken());
        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                $user->getAuthIdentifier(),
                [
                    'rti' => $refreshTokenIdentifier,
                ],
                null
            )
            ->once();
        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                $user->getAuthIdentifier(),
                [
                    'rti' => $refreshTokenIdentifier,
                ],
                $accessTokenTTL
            )
            ->once();
        $refreshTokenRepository
            ->shouldHaveReceived('storeRefreshToken')
            ->with($refreshToken)
            ->once();
        $jwtGuard
            ->shouldHaveReceived('setRefreshToken')
            ->with($refreshToken)
            ->once();
        $jwtGuard
            ->shouldHaveReceived('setAccessToken')
            ->with($accessToken)
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshTokenWithTTL(): void
    {
        $refreshToken = $this->createJWT();
        $refreshTokenTTL = $this->getFaker()->numberBetween();
        $jwtHandler = $this->createJWTHandler();
        $jwtHandler
            ->shouldReceive('createJWT')
            ->andReturn($refreshToken, $this->createJWT());

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            null,
            null,
            null,
            $refreshTokenTTL,
            $this->createRefreshTokenRepository()
        );
        $this->addGetAccessToken($jwtGuard, $this->createJWT());
        $jwtGuard->setUser($this->createUser());

        $this->assertEquals($refreshToken, $jwtGuard->issueRefreshToken());
        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                Mockery::any(),
                Mockery::any(),
                $refreshTokenTTL
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testIssueRefreshTokenWithTokenBlacklist(): void
    {
        $refreshToken = $this->createJWT();
        $accessToken = $this->createJWT();
        $tokenBlacklist = $this->createTokenBlacklist();
        $jwtHandler = $this->createJWTHandler();
        $jwtHandler
            ->shouldReceive('createJWT')
            ->andReturn($refreshToken, $this->createJWT());

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            $this->getFaker()->numberBetween(),
            $tokenBlacklist,
            null,
            null,
            $this->createRefreshTokenRepository()
        );
        $this->addGetAccessToken($jwtGuard, $accessToken);
        $jwtGuard->setUser($this->createUser());

        $this->assertEquals($refreshToken, $jwtGuard->issueRefreshToken());
        $tokenBlacklist
            ->shouldHaveReceived('revoke')
            ->with($accessToken)
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshTokenWithoutRefreshTokenRepository(): void
    {
        $this->expectException(MissingRefreshTokenRepositoryException::class);

        $this->createJWTGuard()->issueRefreshToken();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshTokenWithoutLoggedInUser(): void
    {
        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            $this->createRefreshTokenRepository()
        );
        $this->addGetAccessToken($jwtGuard, $this->createJWT());

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->issueRefreshToken();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshTokenWithoutAccessToken(): void
    {
        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            $this->createRefreshTokenRepository()
        );
        $jwtGuard->setUser($this->createUser());

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->issueRefreshToken();

    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessToken(): void
    {
        $accessTokenTTL = $this->getFaker()->numberBetween();
        $refreshToken = $this->createJWT();
        $refreshToken
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);
        $accessToken = $this->createJWT();
        $user = $this->createUser(
            null,
            $this->getFaker()->uuid,
            null,
            [
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]
        );

        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandler();
        $this
            ->addGetValidJWT($jwtHandler, $refreshToken)
            ->addCreateJWT($jwtHandler, $accessToken);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            null,
            null,
            $accessTokenTTL,
            $tokenBlacklist,
            $this->createRefreshTokenProvider($this->getFaker()->uuid)
        );

        $this->assertEquals($accessToken, $jwtGuard->refreshAccessToken());
        $this->assertEquals($accessToken, $jwtGuard->getAccessToken());
        $this->assertEquals($user, $jwtGuard->user());

        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                $user->getAuthIdentifier(),
                \array_merge(
                    $user->getCustomClaims(),
                    [JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshToken->getRefreshTokenId()]
                ),
                $accessTokenTTL
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessTokenWithRefreshTokenFromGuard(): void
    {
        $accessTokenTTL = $this->getFaker()->numberBetween();
        $refreshToken = $this->createJWT();
        $refreshToken
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);
        $accessToken = $this->createJWT();
        $user = $this->createUser(
            null,
            $this->getFaker()->uuid,
            null,
            [
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]
        );

        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandler();
        $this
            ->addGetValidJWT($jwtHandler, $refreshToken)
            ->addCreateJWT($jwtHandler, $accessToken);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            null,
            null,
            $accessTokenTTL,
            $tokenBlacklist
        );
        $this->addGetRefreshToken($jwtGuard, $refreshToken);

        $this->assertEquals($accessToken, $jwtGuard->refreshAccessToken());
        $this->assertEquals($accessToken, $jwtGuard->getAccessToken());
        $this->assertEquals($user, $jwtGuard->user());

        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                $user->getAuthIdentifier(),
                \array_merge(
                    $user->getCustomClaims(),
                    [JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshToken->getRefreshTokenId()]
                ),
                $accessTokenTTL
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessTokenWithoutRefreshToken(): void
    {
        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            null,
            $this->createRefreshTokenProvider()
        );

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->refreshAccessToken();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessTokenWithoutValidRefreshToken(): void
    {
        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, new InvalidTokenException());

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            null,
            $tokenBlacklist,
            $this->createRefreshTokenProvider($this->getFaker()->uuid)
        );

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->refreshAccessToken();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessTokenWithRevokedRefreshToken(): void
    {
        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, true);

        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            $tokenBlacklist,
            $this->createRefreshTokenProvider($this->getFaker()->uuid)
        );

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->refreshAccessToken();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessTokenWithoutUser(): void
    {
        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, false);

        $refreshToken = $this->createJWT();
        $refreshToken
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $refreshToken);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider(),
            null,
            null,
            null,
            $tokenBlacklist,
            $this->createRefreshTokenProvider($this->getFaker()->uuid)
        );

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->refreshAccessToken();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessTokenWithoutRefreshTokenId(): void
    {
        $tokenBlacklist = $this->createTokenBlacklist();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $this->createJWT());

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            null,
            $tokenBlacklist,
            $this->createRefreshTokenProvider($this->getFaker()->uuid)
        );

        $this->expectException(NotAuthenticatedException::class);

        $jwtGuard->refreshAccessToken();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testReturnAccessToken(): void
    {
        $response = new Response();
        $responseWithToken = new Response();
        $jwt = $this->getFaker()->uuid;
        $accessToken = $this->createJWT();
        $accessToken
            ->shouldReceive('getJWT')
            ->andReturn($this->getFaker()->uuid);
        $accessTokenProvider = $this->createAccessTokenProvider(null, $responseWithToken);

        $jwtGuard = $this->createJWTGuard(null, null, null, $accessTokenProvider);
        $this->addGetAccessToken($jwtGuard, $accessToken);

        $this->assertEquals($responseWithToken, $jwtGuard->returnAccessToken($response));

        $accessTokenProvider
            ->shouldHaveReceived('setResponseToken')
            ->with($response, $accessToken->getJWT())
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testReturnAccessTokenWithoutAccessToken(): void
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->createJWTGuard()->returnAccessToken(new Response());
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testReturnRefreshToken(): void
    {
        $response = new Response();
        $responseWithToken = new Response();
        $responseWithToken->headers->set($this->getFaker()->uuid, $this->getFaker()->uuid);
        $refreshToken = $this->createJWT();
        $refreshToken
            ->shouldReceive('getJWT')
            ->andReturn($this->getFaker()->uuid);
        $refreshTokenProvider = $this->createRefreshTokenProvider(null, $responseWithToken);

        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            null,
            $refreshTokenProvider
        );
        $this->addGetRefreshToken($jwtGuard, $refreshToken);

        $this->assertEquals($responseWithToken, $jwtGuard->returnRefreshToken($response));

        $refreshTokenProvider
            ->shouldHaveReceived('setResponseToken')
            ->with(
                $response,
                $refreshToken->getJWT()
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws NotAuthenticatedException
     */
    public function testReturnRefreshTokenWithoutRefreshToken(): void
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            null,
            $this->createRefreshTokenProvider()
        )->returnRefreshToken(new Response());
    }

    /**
     * @return void
     *
     * @throws NotAuthenticatedException
     */
    public function testReturnRefreshTokenWithoutRefreshTokenProvider(): void
    {
        $this->expectException(MissingRefreshTokenProviderException::class);

        $this->createJWTGuard()->returnRefreshToken(new Response());
    }

    //endregion

    /**
     * @param JWTHandler|null             $jwtHandler
     * @param UserProvider|null           $userProvider
     * @param Request|null                $request
     * @param TokenProvider|null          $accessTokenProvider
     * @param int|null                    $accessTokenTTL
     * @param TokenBlacklist|null         $tokenBlacklist
     * @param TokenProvider|null          $refreshTokenProvider
     * @param int|null                    $refreshTokenTTL
     * @param RefreshTokenRepository|null $refreshTokenRepository
     *
     * @return JWTGuard|MockInterface
     */
    private function createJWTGuard(
        JWTHandler $jwtHandler = null,
        UserProvider $userProvider = null,
        Request $request = null,
        TokenProvider $accessTokenProvider = null,
        int $accessTokenTTL = null,
        TokenBlacklist $tokenBlacklist = null,
        TokenProvider $refreshTokenProvider = null,
        int $refreshTokenTTL = null,
        RefreshTokenRepository $refreshTokenRepository = null
    ): JWTGuard
    {
        $jwtGuard = Mockery::spy(
            JWTGuard::class,
            [
                $jwtHandler ?: $this->createJWTHandler(),
                $userProvider ?: $this->createUserProvider(),
                $request ?: new Request(),
                $accessTokenProvider ?: $this->createAccessTokenProvider(),
                $accessTokenTTL ?: $this->getFaker()->numberBetween(),
                $tokenBlacklist,
                $refreshTokenProvider,
                $refreshTokenTTL,
                $refreshTokenRepository,
            ]
        );
        $jwtGuard
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        return $jwtGuard;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     * @param JWT|null               $accessToken
     *
     * @return JWTGuardTest
     */
    private function addGetAccessToken(JWTGuard $jwtGuard, JWT $accessToken = null): JWTGuardTest
    {
        $jwtGuard
            ->shouldReceive('getAccessToken')
            ->andReturn($accessToken);

        return $this;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     *
     * @param JWT|null               $refreshToken
     * @return JWTGuardTest
     */
    private function addGetRefreshToken(JWTGuard $jwtGuard, JWT $refreshToken = null): JWTGuardTest
    {
        $jwtGuard
            ->shouldReceive('getRefreshToken')
            ->andReturn($refreshToken);

        return $this;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     * @param string|null            $refreshTokenIdentifier
     *
     * @return JWTGuardTest
     */
    private function addCreateRefreshTokenIdentifier(
        JWTGuard $jwtGuard,
        string $refreshTokenIdentifier = null
    ): JWTGuardTest
    {
        $jwtGuard
            ->shouldReceive('createRefreshTokenIdentifier')
            ->andReturn($refreshTokenIdentifier);

        return $this;
    }

    /**
     * @param JWTHandler|MockInterface $jwtHandler
     * @param JWT|Exception            $jwt
     *
     * @return JWTGuardTest
     */
    private function addGetValidJWT(JWTHandler $jwtHandler, $jwt): JWTGuardTest
    {
        $getValidJWTExpectation = $jwtHandler->shouldReceive('getValidJWT');

        if ($jwt instanceof \Exception) {
            $getValidJWTExpectation->andThrow($jwt);

            return $this;
        }

        $getValidJWTExpectation->andReturn($jwt);

        return $this;
    }

    /**
     * @param JWTHandler|MockInterface $jwtHandler
     * @param JWT                      $jwt
     *
     * @return JWTGuardTest
     */
    private function addCreateJWT(JWTHandler $jwtHandler, JWT $jwt): JWTGuardTest
    {
        $jwtHandler
            ->shouldReceive('createJWT')
            ->andReturn($jwt);

        return $this;
    }

    /**
     * @param Authenticatable|null $user
     * @param bool                 $validCredentials
     *
     * @return UserProvider|MockInterface
     */
    private function createUserProvider(Authenticatable $user = null, bool $validCredentials = false): UserProvider
    {
        $userProvider = Mockery::spy(UserProvider::class);

        $userProvider
            ->shouldReceive('retrieveById')
            ->andReturn($user);

        $userProvider
            ->shouldReceive('retrieveByToken')
            ->andReturn($user);

        $userProvider
            ->shouldReceive('retrieveByCredentials')
            ->andReturn($user);

        $userProvider
            ->shouldReceive('validateCredentials')
            ->andReturn($validCredentials);

        return $userProvider;
    }

    /**
     * @param string|null $authIdentifierName
     * @param string|null $authIdentifier
     * @param string|null $authPassword
     * @param array       $customClaims
     *
     * @return JWTAuthenticatable|MockInterface
     */
    private function createUser(
        string $authIdentifierName = null,
        string $authIdentifier = null,
        string $authPassword = null,
        array $customClaims = []
    ): JWTAuthenticatable
    {
        $user = Mockery::spy(JWTAuthenticatable::class);

        $user
            ->shouldReceive('getAuthIdentifierName')
            ->andReturn($authIdentifierName ?: $this->getFaker()->uuid);

        $user
            ->shouldReceive('getAuthIdentifier')
            ->andReturn($authIdentifier ?: $this->getFaker()->uuid);

        $user
            ->shouldReceive('getAuthPassword')
            ->andReturn($authPassword ?: $this->getFaker()->password);

        $user
            ->shouldReceive('getCustomClaims')
            ->andReturn($customClaims);

        return $user;
    }

    /**
     * @param string|null   $token
     * @param Response|null $response
     *
     * @return TokenProvider|MockInterface
     */
    private function createAccessTokenProvider(string $token = null, Response $response = null): TokenProvider
    {
        $accessTokenProvider = Mockery::spy(TokenProvider::class);

        $accessTokenProvider
            ->shouldReceive('getRequestToken')
            ->andReturn($token);

        $accessTokenProvider
            ->shouldReceive('setResponseToken')
            ->andReturn($response);

        return $accessTokenProvider;
    }

    /**
     * @param string|null   $token
     * @param Response|null $response
     *
     * @return TokenProvider|MockInterface
     */
    private function createRefreshTokenProvider(string $token = null, Response $response = null): TokenProvider
    {
        $refreshTokenProvider = Mockery::spy(TokenProvider::class);

        $refreshTokenProvider
            ->shouldReceive('getRequestToken')
            ->andReturn($token);

        $refreshTokenProvider
            ->shouldReceive('setResponseToken')
            ->andReturn($response);

        return $refreshTokenProvider;
    }

    /**
     * @return TokenBlacklist|MockInterface
     */
    private function createTokenBlacklist(): TokenBlacklist
    {
        return Mockery::spy(TokenBlacklist::class);
    }

    /**
     * @param TokenBlacklist|MockInterface $tokenBlacklist
     * @param bool                         $isRevoked
     *
     * @return JWTGuardTest
     */
    private function addIsRevoked(TokenBlacklist $tokenBlacklist, bool $isRevoked): JWTGuardTest
    {
        $tokenBlacklist
            ->shouldReceive('isRevoked')
            ->andReturn($isRevoked);

        return $this;
    }
}
