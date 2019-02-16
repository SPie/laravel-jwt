<?php

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Http\Request;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Mockery\MockInterface;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Blacklist\CacheTokenBlacklist;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\MissingRefreshTokenRepositoryException;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class JWTGuardTest
 */
class JWTGuardTest extends TestCase
{

    use JWTHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUser(): void
    {
        $user = $this->createUser();

        $this->assertEquals(
            $user,
            $this->createJWTGuard(
                $this->createJWTHandler($this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid,]))),
                $this->createUserProvider($user),
                new Request(),
                $this->createAccessTokenProvider($this->createToken())
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
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
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserEmptyToken(): void
    {
        $this->assertEmpty($this->createJWTGuard()->user());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserInvalidToken(): void
    {
        $this->assertEmpty(
            $this->createJWTGuard(
                $this->createJWTHandler()->setJWTException(new InvalidTokenException()),
                null,
                null,
                $this->createAccessTokenProvider($this->createToken())
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserWithEmptyBlacklist(): void
    {
        $user = $this->createUser();

        $this->assertEquals(
            $user,
            $this->createJWTGuard(
                $this->createJWTHandler($this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid,]))),
                $this->createUserProvider($user),
                new Request(),
                $this->createAccessTokenProvider($this->createToken()),
                $this->createTokenBlacklist(new ArrayStore())
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserWithRevokedToken(): void
    {
        $jwt = $this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid,]));
        $arrayStore = new ArrayStore();
        $arrayStore->put(\md5($jwt->getJWT()), $jwt->getJWT(), 60);

        $this->assertEmpty(
            $this->createJWTGuard(
                $this->createJWTHandler($jwt),
                $this->createUserProvider($this->createUser()),
                new Request(),
                $this->createAccessTokenProvider($jwt->getJWT()),
                $this->createTokenBlacklist($arrayStore)
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws \Exception
     */
    public function testUserWithoutRevokedRefreshToken(): void
    {
        $user = $this->createUser();

        $this->assertEquals(
            $user,
            $this->createJWTGuard(
                $this->createJWTHandler($this->createJWT(
                    $this->createToken([
                        JWT::CLAIM_SUBJECT              => $this->getFaker()->uuid,
                        JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $this->getFaker()->uuid,
                    ])
                )),
                $this->createUserProvider($user),
                new Request(),
                $this->createAccessTokenProvider($this->createToken()),
                null,
                null,
                $this->createRefreshTokenRepository()
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws \Exception
     */
    public function testUserWithRevokedRefreshToken(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository->getDisabledRefreshTokens()->push($refreshTokenId);

        $this->assertEmpty(
            $this->createJWTGuard(
                $this->createJWTHandler($this->createJWT(
                    $this->createToken([
                        JWT::CLAIM_SUBJECT              => $this->getFaker()->uuid,
                        JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshTokenId,
                    ])
                )),
                $this->createUserProvider($this->createUser()),
                new Request(),
                $this->createAccessTokenProvider($this->createToken()),
                null,
                null,
                $refreshTokenRepository
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     */
    public function testValidate(): void
    {
        $this->assertTrue(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser())->setValidCredentials(true)
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
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
     *
     * @throws InvalidSecretException
     */
    public function testValidateWithInvalidCredentials(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser())->setValidCredentials(false)
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testIssueAccessToken(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $user->getAuthIdentifier()]));

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            $this->createUserProvider($user),
            new Request(),
            $this->createAccessTokenProvider()
        );

        $this->assertEquals($jwt, $jwtGuard->issueAccessToken($user));
        $this->assertEquals($jwt, $jwtGuard->getAccessToken());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws AuthorizationException
     * @throws Exception
     */
    public function testLogin(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            $this->createUserProvider($user)->setValidCredentials(true),
            new Request(),
            $this->createAccessTokenProvider()
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
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLoginWithoutUser(): void
    {
        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($this->createJWT()),
            $this->createUserProvider(),
            new Request(),
            $this->createAccessTokenProvider()
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
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLoginWithoutJWTAuthenticatable(): void
    {
        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($this->createJWT()),
            $this->createUserProvider(
                new class implements Authenticatable {
                    public function getAuthIdentifierName() {}
                    public function getAuthIdentifier() {}
                    public function getAuthPassword() {}
                    public function getRememberToken() {}
                    public function setRememberToken($value) {}
                    public function getRememberTokenName() {}
                }
            ),
            new Request(),
            $this->createAccessTokenProvider()
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
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLoginWithInvalidCredentials(): void
    {
        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($this->createJWT()),
            $this->createUserProvider($this->createUser())->setValidCredentials(false),
            new Request(),
            $this->createAccessTokenProvider()
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
     * @throws \Exception
     */
    public function testLogout(): void
    {
        $jwt = $this->createJWT($this->createToken());
        $arrayStore = new ArrayStore();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            null,
            new Request(),
            $this->createAccessTokenProvider(),
            $this->createTokenBlacklist($arrayStore)
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $jwt);

        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
        $this->assertEquals($jwt->getJWT(), $arrayStore->get(\md5($jwt->getJWT())));
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLogoutWithoutTokenBlacklist(): void
    {
        $jwt = $this->createJWT($this->createToken());

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            null,
            new Request(),
            $this->createAccessTokenProvider()
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $jwt);

        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLogoutWithoutJWT(): void
    {
        $jwt = $this->createJWT($this->createToken());
        $arrayStore = new ArrayStore();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            null,
            new Request(),
            $this->createAccessTokenProvider(),
            $this->createTokenBlacklist($arrayStore)
        );

        $jwtGuard->setUser($this->createUser());
        $jwtGuard->logout();

        $arrayStoreObject = new \ReflectionObject($arrayStore);
        $storageProperty = $arrayStoreObject->getProperty('storage');
        $storageProperty->setAccessible(true);

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($storageProperty->getValue($arrayStore));
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws \Exception
     */
    public function testLogoutWithRefreshToken(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;

        $jwt = $this->createJWT($this->createToken([
            JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshTokenId,
        ]));
        $arrayStore = new ArrayStore();
        $refreshTokenRepository = $this->createRefreshTokenRepository();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            null,
            new Request(),
            $this->createAccessTokenProvider(),
            $this->createTokenBlacklist($arrayStore),
            null,
            $refreshTokenRepository
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $jwt);

        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
        $this->assertEquals($jwt->getJWT(), $arrayStore->get(\md5($jwt->getJWT())));
        $this->assertEquals($refreshTokenId, $refreshTokenRepository->getDisabledRefreshTokens()->first());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws \Exception
     */
    public function testLogoutWithoutRefreshToken(): void
    {
        $jwt = $this->createJWT($this->createToken());
        $arrayStore = new ArrayStore();
        $refreshTokenRepository = $this->createRefreshTokenRepository();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            null,
            new Request(),
            $this->createAccessTokenProvider(),
            $this->createTokenBlacklist($arrayStore),
            null,
            $refreshTokenRepository
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $jwt);

        $jwtGuard->setUser($this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($jwtGuard->getAccessToken());
        $this->assertEmpty($jwtGuard->user());
        $this->assertEquals($jwt->getJWT(), $arrayStore->get(\md5($jwt->getJWT())));
        $this->assertEmpty($refreshTokenRepository->getDisabledRefreshTokens()->first());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshToken(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT($this->createToken());
        $refreshTokenRepository = $this->createRefreshTokenRepository();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler(),
            $this->createUserProvider($user),
            new Request(),
            $this->createAccessTokenProvider($jwt->getJWT()),
            null,
            null,
            $refreshTokenRepository
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $jwt);
        $jwtGuard->setUser($user);

        $refreshJwt = $jwtGuard->issueRefreshToken();

        $this->assertNotEmpty($refreshJwt);
        $this->assertTrue($refreshTokenRepository->getRefreshTokens()->containsStrict($refreshJwt));
        $this->assertNotEmpty($refreshJwt->getRefreshTokenId());
        $this->assertNotEmpty($jwtGuard->getAccessToken());
        $this->assertNotEquals($jwt, $jwtGuard->getAccessToken());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws \Exception
     */
    public function testIssueRefreshTokenWithTokenBlacklist(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT($this->createToken());
        $arrayStore = new ArrayStore();
        $refreshTokenRepository = $this->createRefreshTokenRepository();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler(),
            $this->createUserProvider($user),
            new Request(),
            $this->createAccessTokenProvider($jwt->getJWT()),
            $this->createTokenBlacklist($arrayStore),
            null,
            $refreshTokenRepository
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $jwt);
        $jwtGuard->setUser($user);

        $refreshJwt = $jwtGuard->issueRefreshToken();

        $this->assertNotEmpty($refreshJwt);
        $this->assertTrue($refreshTokenRepository->getRefreshTokens()->containsStrict($refreshJwt));
        $this->assertNotEmpty($refreshJwt->getRefreshTokenId());
        $this->assertNotEmpty($jwtGuard->getAccessToken());
        $this->assertNotEquals($jwt, $jwtGuard->getAccessToken());
        $this->assertNotEmpty($arrayStore->get(\md5($jwt->getJWT())));
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIssueRefreshTokenWithoutRefreshTokenRepository(): void
    {
        try {
            $this->createJWTGuard()->issueRefreshToken();

            $this->assertTrue(false);
        } catch (MissingRefreshTokenRepositoryException $e) {
            $this->assertTrue(true);
        }
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
            $this->createRefreshTokenRepository()
        );

        $setJwtMethod = (new \ReflectionObject($jwtGuard))->getMethod('setAccessToken');
        $setJwtMethod->setAccessible(true);
        $setJwtMethod->invoke($jwtGuard, $this->createJWT($this->createToken()));

        try {
            $jwtGuard->issueRefreshToken();

            $this->assertTrue(false);
        } catch (NotAuthenticatedException $e) {
            $this->assertTrue(true);
        }
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
            $this->createRefreshTokenRepository()
        );
        $jwtGuard->setUser($this->createUser());

        try {
            $jwtGuard->issueRefreshToken();

            $this->assertTrue(false);
        } catch (NotAuthenticatedException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testRefreshAccessToken(): void
    {
        $refreshToken = $this->createJWT($this->createRefreshToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid]));
        $accessToken = $this->createJWT();
        $user = $this->createUserMock(
            null,
            $refreshToken->getSubject(),
            null,
            [
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]
        );

        $tokenBlacklist = $this->createTokenBlacklistMock();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandlerMock();
        $this
            ->addGetValidJWT($jwtHandler, $refreshToken)
            ->addCreateJWT($jwtHandler, $accessToken);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProviderMock($user),
            null,
            null,
            $tokenBlacklist,
            $this->createRefreshTokenProvider($refreshToken->getToken())
        );

        $this->assertEquals($accessToken, $jwtGuard->refreshAccessToken());
        $this->assertEquals($accessToken, $jwtGuard->getAccessToken());
        $this->assertEquals($user, $jwtGuard->user());

        $jwtHandler
            ->shouldHaveReceived('createJWT')
            ->with(
                $refreshToken->getSubject(),
                \array_merge(
                    $user->getCustomClaims(),
                    [JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshToken->getRefreshTokenId()]
                )
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
        $tokenBlacklist = $this->createTokenBlacklistMock();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandlerMock();
        $this->addGetValidJWT($jwtHandler, new InvalidTokenException());

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
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
        $tokenBlacklist = $this->createTokenBlacklistMock();
        $this->addIsRevoked($tokenBlacklist, true);

        $jwtGuard = $this->createJWTGuard(
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
        $tokenBlacklist = $this->createTokenBlacklistMock();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandlerMock();
        $this->addGetValidJWT(
            $jwtHandler,
            $this->createJWT($this->createRefreshToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid]))
        );

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProviderMock(),
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
        $tokenBlacklist = $this->createTokenBlacklistMock();
        $this->addIsRevoked($tokenBlacklist, false);

        $jwtHandler = $this->createJWTHandlerMock();
        $this->addGetValidJWT(
            $jwtHandler,
            $this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid]))
        );

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
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
        $responseWithToken->headers->set($this->getFaker()->uuid, $this->getFaker()->uuid);
        $accessToken = $this->createJWT();
        $accessTokenProvider = $this->createAccessTokenProviderMock(null, $responseWithToken);

        $jwtGuard = $this->createJWTGuard(null, null, null, $accessTokenProvider);
        $this->addGetAccessToken($jwtGuard, $accessToken);

        $this->assertEquals($responseWithToken, $jwtGuard->returnAccessToken($response));

        $accessTokenProvider
            ->shouldHaveReceived('setResponseToken')
            ->with(
                $response,
                $accessToken->getJWT()
            )
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
        $refreshTokenProvider = $this->createRefreshTokenProvider(null, $responseWithToken);

        $jwtGuard = $this->createJWTGuard(
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
     * @throws InvalidSecretException
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
            $this->createRefreshTokenProvider()
        )->returnRefreshToken(new Response());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws NotAuthenticatedException
     */
    public function testReturnRefreshTokenWithoutRefreshTokenProvider(): void
    {
        $response = new Response();

        $this->assertEquals($response, $this->createJWTGuard()->returnRefreshToken($response));
    }

    //endregion

    /**
     * @param JWTHandler|null             $jwtHandler
     * @param UserProvider|null           $userProvider
     * @param Request|null                $request
     * @param TokenProvider|null          $accessTokenProvider
     * @param TokenBlacklist|null         $tokenBlacklist
     * @param TokenProvider|null          $refreshTokenProvider
     * @param RefreshTokenRepository|null $refreshTokenRepository
     *
     * @return JWTGuard|MockInterface
     *
     * @throws InvalidSecretException
     */
    private function createJWTGuard(
        JWTHandler $jwtHandler = null,
        UserProvider $userProvider = null,
        Request $request = null,
        TokenProvider $accessTokenProvider = null,
        TokenBlacklist $tokenBlacklist = null,
        TokenProvider $refreshTokenProvider = null,
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
                $tokenBlacklist,
                $refreshTokenProvider,
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
     * @param JWT|null $jwt
     *
     * @return TestJWTHandler
     *
     * @throws InvalidSecretException
     */
    private function createJWTHandler(JWT $jwt = null): TestJWTHandler
    {
        return (new TestJWTHandler(
            $this->getFaker()->uuid,
            $this->getFaker()->uuid,
            $this->getFaker()->numberBetween()
        ))->setJWT($jwt);
    }

    /**
     * @param string|null $secret
     * @param string|null $issuer
     * @param int|null    $ttl
     * @param Signer|null $signer
     *
     * @return JWTHandler|MockInterface
     */
    private function createJWTHandlerMock(
        string $secret = null,
        string $issuer = null,
        int $ttl = null,
        Signer $signer = null
    ): JWTHandler
    {
        return Mockery::spy(
            JWTHandler::class,
            [
                $secret ?: $this->getFaker()->password,
                $issuer ?: $this->getFaker()->uuid,
                $ttl ?: $this->getFaker()->numberBetween(),
                $signer
            ]
        )->makePartial();
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
     * @param JWTHandler|MockInterface $jwtHandler
     * @param JWT|\Exception $jwt
     *
     * @return JWTGuardTest
     */
    private function addGetValidJWT(JWTHandler $jwtHandler, $jwt): JWTGuardTest
    {
        $getValidJwtExpectation = $jwtHandler->shouldReceive('getValidJWT');

        if ($jwt instanceof \Exception) {
            $getValidJwtExpectation->andThrow($jwt);

            return $this;
        }

        $getValidJwtExpectation->andReturn($jwt);

        return $this;
    }

    /**
     * @param Authenticatable|null $user
     *
     * @return TestUserProvider
     */
    private function createUserProvider(Authenticatable $user = null): TestUserProvider
    {
        return (new TestUserProvider())->setUser($user);
    }

    /**
     * @param Authenticatable|null $user
     * @param bool                 $validCredentials
     *
     * @return UserProvider|MockInterface
     */
    private function createUserProviderMock(Authenticatable $user = null, bool $validCredentials = false): UserProvider
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
     *
     * @return JWTAuthenticatable
     */
    private function createUser(
        string $authIdentifierName = null,
        string $authIdentifier = null,
        string $authPassword = null
    ): JWTAuthenticatable
    {
        return new TestUser(
            $authIdentifierName ?? $this->getFaker()->uuid,
            $authIdentifier ?? $this->getFaker()->uuid,
            $authPassword ?? $this->getFaker()->password
        );
    }

    /**
     * @param string|null $authIdentifierName
     * @param string|null $authIdentifier
     * @param string|null $authPassword
     * @param array       $customClaims
     *
     * @return JWTAuthenticatable|MockInterface
     */
    private function createUserMock(
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
     * @param string|null $token
     *
     * @return TokenProvider
     */
    private function createAccessTokenProvider(string $token = null): TokenProvider
    {
        return (new TestTokenProvider())->setToken($token);
    }

    /**
     * @param string|null   $token
     * @param Response|null $response
     *
     * @return TokenProvider|MockInterface
     */
    private function createAccessTokenProviderMock(string $token = null, Response $response = null): TokenProvider
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
     * @param Token|null $token
     *
     * @return JWT
     *
     * @throws \Exception
     */
    private function createJWT(Token $token = null): JWT
    {
        return new JWT($token ?: $this->createToken());
    }

    /**
     * @param Store $store
     *
     * @return CacheTokenBlacklist
     */
    private function createTokenBlacklist(Store $store): CacheTokenBlacklist
    {
        return new CacheTokenBlacklist(new Repository($store));
    }

    /**
     * @return TokenBlacklist|MockInterface
     */
    private function createTokenBlacklistMock(): TokenBlacklist
    {
        return Mockery::spy(TokenBlacklist::class);
    }

    /**
     * @param TokenBlacklist|MockInterface $tokenBlacklist
     *
     * @return JWTGuardTest
     */
    private function addRevoke(TokenBlacklist $tokenBlacklist): JWTGuardTest
    {
        $tokenBlacklist
            ->shouldReceive('revoke')
            ->andReturn($tokenBlacklist);

        return $this;
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

    /**
     * @return TestRefreshTokenRepository
     */
    private function createRefreshTokenRepository(): TestRefreshTokenRepository
    {
        return new TestRefreshTokenRepository();
    }
}
