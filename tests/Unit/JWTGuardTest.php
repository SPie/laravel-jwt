<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Auth\JWTGuardConfig;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Events\RefreshAccessToken;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTHandler;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\RequestHelper;
use SPie\LaravelJWT\Test\TestHelper;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class JWTGuardTest
 */
final class JWTGuardTest extends TestCase
{
    use TestHelper;
    use JWTHelper;
    use ReflectionMethodHelper;
    use RequestHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws \Exception
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
            null,
            $this->createAccessTokenProvider($this->getFaker()->uuid)
        );

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($jwt, $this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
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
     */
    public function testUserEmptyToken(): void
    {
        $this->assertEmpty($this->createJWTGuard()->user());
    }

    /**
     * @return void
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
                null,
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                $tokenBlacklist
            )->user()
        );
    }

    /**
     * @return void
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
                null,
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                $tokenBlacklist
            )->user()
        );
    }

    /**
     * @return void
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
                null,
                $this->createAccessTokenProvider($this->getFaker()->uuid),
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
                null,
                $this->createAccessTokenProvider($this->getFaker()->uuid),
                null,
                null,
                $refreshTokenRepository
            )->user()
        );
    }

    /**
     * @return void
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
            null,
            null,
            null,
            $this->createRefreshTokenProvider($this->getFaker()->uuid),
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
                null,
                null,
                null,
                $this->createRefreshTokenProvider()
            )->user()
        );
    }

    /**
     * @return void
     */
    public function testUserWithInvalidRefreshToken(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, new InvalidSecretException());

        $this->assertEmpty(
            $this->createJWTGuard(
                $jwtHandler,
                null,
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
                null,
                null,
                null,
                $this->createRefreshTokenProvider($this->getFaker()->uuid),
                $refreshTokenRepository
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithValidIpCheckOnAccessToken(): void
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $ipAddress = $this->getFaker()->ipv4;
        $request = $this->createRequestWithIp($ipAddress);
        $jwt = $this->createJWT();
        $this->mockJWTGetIpAddress($jwt, $ipAddress);
        $this->addGetValidJWT(
            $jwtHandler,
            $jwt
        );
        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            $this->createJWTGuardConfig(true),
            $this->createAccessTokenProvider($this->getFaker()->uuid),
            null,
            null,
            null,
            null,
            $request,
        );

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($jwt, $this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithIpCheckWithoutIpAddressInToken(): void
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $request = $this->createRequestWithIp($this->getFaker()->ipv4);
        $jwt = $this->createJWT();
        $this->mockJWTGetIpAddress($jwt, null);
        $this->addGetValidJWT(
            $jwtHandler,
            $jwt
        );

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            $this->createJWTGuardConfig(true),
            $this->createAccessTokenProvider($this->getFaker()->uuid),
            null,
            null,
            null,
            null,
            $request
        );

        $this->assertEquals($user, $jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testUserWithInvalidIpCheckOnAccessToken(): void
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $request = $this->createRequestWithIp($this->getFaker()->ipv4);
        $jwt = $this->createJWT();
        $this->mockJWTGetIpAddress($jwt, $this->getFaker()->localIpv4);
        $this->addGetValidJWT(
            $jwtHandler,
            $jwt
        );

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            $this->createJWTGuardConfig(true),
            $this->createAccessTokenProvider($this->getFaker()->uuid),
            null,
            null,
            null,
            null,
            $request
        );

        $this->assertEmpty($jwtGuard->user());
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
     */
    public function testUserWithRefreshTokenWithValidIpCheck(): void
    {
        $ipAddress = $this->getFaker()->ipv4;
        $user = $this->createUser();
        $jwt = $this->createJWT();
        $this->mockJWTGetIpAddress($jwt, $ipAddress);
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);
        $request = $this->createRequestWithIp($ipAddress);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->andReturn(false);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            $this->createJWTGuardConfig(true),
            null,
            null,
            $this->createRefreshTokenProvider($this->getFaker()->uuid),
            $refreshTokenRepository,
            null,
            $request
        );

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($jwt, $jwtGuard->getRefreshToken());
    }

    /**
     * @return void
     */
    public function testUserWithRefreshTokenWithInvalidIpCheck(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT();
        $this->mockJWTGetIpAddress($jwt, $this->getFaker()->ipv4);
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($this->getFaker()->uuid);
        $request = $this->createRequestWithIp($this->getFaker()->localIpv4);

        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->andReturn(false);

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $this->createUserProvider($user),
            $this->createJWTGuardConfig(true),
            null,
            null,
            $this->createRefreshTokenProvider($this->getFaker()->uuid),
            $refreshTokenRepository,
            null,
            $request,
        );

        $this->assertEmpty($jwtGuard->user());
        $this->assertEmpty($jwtGuard->getRefreshToken());
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

    private function setUpIssueAccessToken(JWTAuthenticatable $user, JWTHandler $jwtHandler, string $ipAddress = null): array
    {
        $ttl = $this->getFaker()->numberBetween();
        $accessToken = $this->createJWT();
        $claims = $user->getCustomClaims();
        if (!empty($ipAddress)) {
            $claims['ipa'] = $ipAddress;
        }
        $this->mockJWTHandlerCreateJWT($jwtHandler, $accessToken, $user->getAuthIdentifier(), $claims, $ttl);

        return [$accessToken, $ttl];
    }

    private function setUpIssueRefreshToken(JWTAuthenticatable $user, JWTHandler $jwtHandler, string $ipAddress = null): array
    {
        $refreshTtl = $this->getFaker()->numberBetween();
        $refreshToken = $this->createJWT();
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $claims = $user->getCustomClaims();
        if (!empty($ipAddress)) {
            $claims['ipa'] = $ipAddress;
        }
        $this->mockJWTHandlerCreateJWTForRefreshToken($jwtHandler, $refreshToken, $user->getAuthIdentifier(), $refreshTtl);

        return [$refreshToken, $refreshTtl, $refreshTokenRepository];
    }

    /**
     * @param bool $withIpAddress
     *
     * @return array
     */
    private function setUpLoginTest(bool $withIpAddress = false): array
    {
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $ipAddress = $withIpAddress ? $this->getFaker()->ipv4 : null;
        [$accessToken, $ttl] = $this->setUpIssueAccessToken($user, $jwtHandler, $ipAddress);
        [$refreshToken, $refreshTtl, $refreshTokenRepository] = $this->setUpIssueRefreshToken($user, $jwtHandler, $ipAddress);
        $loginEvent = $this->createLoginEvent();
        $guardName = $this->getFaker()->word;
        $eventFactory = $this->createEventFactory();
        $this->mockEventFactoryCreateLoginEvent($eventFactory, $loginEvent, $guardName, $user, false);
        $dispatcher = $this->createEventDispatcher();
        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            $this->createJWTGuardConfig($withIpAddress, $ttl, $refreshTtl),
            null,
            null,
            null,
            $refreshTokenRepository,
            $dispatcher,
            $withIpAddress ? $this->createRequestWithIp($ipAddress) : null,
            $guardName,
            $eventFactory
        );

        return [$jwtGuard, $user, $accessToken, $dispatcher, $loginEvent, $refreshTokenRepository, $refreshToken];
    }

    /**
     * @return void
     */
    public function testLogin(): void
    {
        /**
         * @var JWTGuard   $jwtGuard
         * @var Dispatcher $dispatcher
         */
        [$jwtGuard, $user, $accessToken, $dispatcher, $login] = $this->setUpLoginTest();

        $jwtGuard->login($user);

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $jwtGuard->getAccessToken());
        $this->assertEventDispatcherDispatch($dispatcher, $login);
    }

    /**
     * @return void
     */
    public function testLoginWithIpAddress(): void
    {
        /** @var JWTGuard   $jwtGuard */
        [$jwtGuard, $user, $accessToken] = $this->setUpLoginTest(true);

        $jwtGuard->login($user);

        $this->assertEquals($accessToken, $jwtGuard->getAccessToken());
    }

    /**
     * @return void
     */
    public function testLoginWithRefreshToken(): void
    {
        /**
         * @var JWTGuard   $jwtGuard
         * @var Dispatcher $dispatcher
         */
        [$jwtGuard, $user, $accessToken, $dispatcher, $login, $refreshTokenRepository, $refreshToken] = $this->setUpLoginTest();

        $jwtGuard->login($user, true);

        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $this->assertRefreshTokenRepositoryStoreRefreshToken($refreshTokenRepository, $refreshToken);
    }

    /**
     * @return void
     */
    public function testLoginWithRefreshTokenWithIpAddress(): void
    {
        /**
         * @var JWTGuard   $jwtGuard
         * @var Dispatcher $dispatcher
         */
        [$jwtGuard, $user, $accessToken, $dispatcher, $login, $refreshTokenRepository, $refreshToken] = $this->setUpLoginTest(true);

        $jwtGuard->login($user, true);

        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $this->assertRefreshTokenRepositoryStoreRefreshToken($refreshTokenRepository, $refreshToken);
    }

    /**
     * @return void
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
            $tokenBlacklist
        );
        $this
            ->setPrivateProperty($jwtGuard, 'accessToken', $jwt)
            ->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $tokenBlacklist
            ->shouldHaveReceived('revoke')
            ->with($jwt)
            ->once();
    }

    /**
     * @return void
     */
    public function testLogoutWithoutTokenBlacklist(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $jwtGuard = $this->createJWTGuard($jwtHandler);
        $this
            ->setPrivateProperty($jwtGuard, 'accessToken', $jwt)
            ->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();


        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    /**
     * @return void
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
            $tokenBlacklist
        );
        $this->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $tokenBlacklist->shouldNotHaveReceived('revoke');
    }

    /**
     * @return void
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
            $this->createTokenBlacklist(),
            null,
            $refreshTokenRepository
        );
        $this
            ->setPrivateProperty($jwtGuard, 'user', $this->createUser())
            ->setPrivateProperty($jwtGuard, 'accessToken', $this->createJWT())
            ->setPrivateProperty($jwtGuard, 'refreshToken', $jwt);

        $jwtGuard->logout();

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $refreshTokenRepository
            ->shouldHaveReceived('revokeRefreshToken')
            ->with($refreshTokenId)
            ->once();
    }

    /**
     * @return void
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
            null,
            $this->createAccessTokenProvider(),
            $tokenBlacklist,
            null,
            $refreshTokenRepository
        );
        $this
            ->setPrivateProperty($jwtGuard, 'accessToken', $jwt)
            ->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();

        $refreshTokenRepository->shouldNotHaveReceived('revokeRefreshToken');
    }

    /**
     * @return void
     */
    public function testLogoutWithLogoutEvent(): void
    {
        $user = $this->createUser();
        $guardName = $this->getFaker()->word;
        $logout = $this->createLogoutEvent();
        $eventFactory = $this->createEventFactory();
        $this->mockEventFactoryCreateLogoutEvent($eventFactory, $logout, $guardName, $user);
        $eventDispatcher = $this->createEventDispatcher();
        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            $eventDispatcher,
            null,
            $guardName,
            $eventFactory,
        );
        $this->setPrivateProperty($jwtGuard, 'user', $user);

        $jwtGuard->logout();

        $this->assertEventDispatcherDispatch($eventDispatcher, $logout);
    }

    /**
     * @return void
     */
    public function testLogoutWithoutAuthenticatedUser(): void
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->createJWTGuard()->logout();
    }

    /**
     * @return void
     */
    public function testReturnAccessToken(): void
    {
        $response = new Response();
        $responseWithToken = new Response();
        $accessToken = $this->createJWT();
        $accessToken
            ->shouldReceive('getJWT')
            ->andReturn($this->getFaker()->uuid);
        $accessTokenProvider = $this->createAccessTokenProvider(null, $responseWithToken);

        $jwtGuard = $this->createJWTGuard(null, null, null, $accessTokenProvider);
        $this->setPrivateProperty($jwtGuard, 'accessToken', $accessToken);

        $this->assertEquals($responseWithToken, $jwtGuard->returnAccessToken($response));

        $accessTokenProvider
            ->shouldHaveReceived('setResponseToken')
            ->with($response, $accessToken->getJWT())
            ->once();
    }

    /**
     * @return void
     */
    public function testReturnAccessTokenWithoutAccessToken(): void
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->createJWTGuard()->returnAccessToken(new Response());
    }

    /**
     * @return void
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
            $refreshTokenProvider
        );
        $this->setPrivateProperty($jwtGuard, 'refreshToken', $refreshToken);

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
            $this->createRefreshTokenProvider()
        )->returnRefreshToken(new Response());
    }

    /**
     * @param bool $remember
     * @param bool $withUser
     * @param bool $withValidCredentials
     *
     * @return array
     */
    private function setUpAttemptTest(
        bool $remember = false,
        bool $withUser = true,
        bool $withValidCredentials = true
    ): array {
        $credentials = [$this->getFaker()->word => $this->getFaker()->word];
        $user = $this->createUser();
        $jwtHandler = $this->createJWTHandler();
        $userProvider = $this->createUserProviderMock();
        $this
            ->mockUserProviderRetrieveByCredentials($userProvider, $withUser ? $user : null, $credentials)
            ->mockUserProviderValidateCredentials($userProvider, $withValidCredentials, $user, $credentials);
        [$accessToken, $ttl] = $this->setUpIssueAccessToken($user, $jwtHandler);
        [$refreshToken, $refreshTtl, $refreshTokenRepository] = $this->setUpIssueRefreshToken($user, $jwtHandler);
        $guardName = $this->getFaker()->word;
        $attemptingEvent = $this->createAttemptingEvent();
        $failedEvent = $this->createFailedEvent();
        $eventFactory = $this->createEventFactory();
        $this
            ->mockEventFactoryCreateAttemptingEvent($eventFactory, $attemptingEvent, $guardName, $credentials, $remember)
            ->mockEventFactoryCreateFailedEvent($eventFactory, $failedEvent, $guardName, $withUser ? $user : null, $credentials);
        $eventDispatcher = $this->createEventDispatcher();
        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $userProvider,
            $this->createJWTGuardConfig(null, $ttl, $refreshTtl),
            null,
            null,
            null,
            $refreshTokenRepository,
            $eventDispatcher,
            null,
            $guardName,
            $eventFactory,
        );

        return [$jwtGuard, $credentials, $user, $accessToken, $refreshToken, $eventDispatcher, $attemptingEvent, $failedEvent];
    }

    /**
     * @return void
     */
    public function testAttempt(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user, $accessToken] = $this->setUpAttemptTest();

        $this->assertTrue($jwtGuard->attempt($credentials));

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
     */
    public function testAttemptWithRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user, $accessToken, $refreshToken] = $this->setUpAttemptTest(true);

        $this->assertTrue($jwtGuard->attempt($credentials, true));

        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    /**
     * @return void
     */
    public function testAttemptWithoutFoundUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [
            $jwtGuard,
            $credentials,
            $user,
            $accessToken,
            $refreshToken,
            $eventDispatcher,
            $attemptingEvent,
            $failedEvent
        ] = $this->setUpAttemptTest(false, false);

        $this->assertFalse($jwtGuard->attempt($credentials));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEventDispatcherDispatch($eventDispatcher, $failedEvent);
    }

    /**
     * @return void
     */
    public function testAttemptWithoutValidCredentials(): void
    {
        /** @var JWTGuard $jwtGuard */
        [
            $jwtGuard,
            $credentials,
            $user,
            $accessToken,
            $refreshToken,
            $eventDispatcher,
            $attemptingEvent,
            $failedEvent
        ] = $this->setUpAttemptTest(false, true, false);

        $this->assertFalse($jwtGuard->attempt($credentials));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEventDispatcherDispatch($eventDispatcher, $failedEvent);
    }

    /**
     * @return void
     */
    public function testAttemptWithEvents(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user, $accessToken, $refreshToken, $eventDispatcher, $attemptingEvent] = $this->setUpAttemptTest();

        $jwtGuard->attempt($credentials);

        $this->assertEventDispatcherDispatch($eventDispatcher, $attemptingEvent);
    }

    /**
     * @param bool $withUser
     * @param bool $withValidCredentials
     *
     * @return array
     */
    private function setUpOnceTest(bool $withUser = true, bool $withValidCredentials = true): array
    {
        $credentials = [$this->getFaker()->word => $this->getFaker()->word];
        $user = $this->createUser();
        $userProvider = $this->createUserProviderMock();
        $this
            ->mockUserProviderRetrieveByCredentials($userProvider, $withUser ? $user : null, $credentials)
            ->mockUserProviderValidateCredentials($userProvider, $withValidCredentials, $user, $credentials);
        $jwtGuard = $this->createJWTGuard(null, $userProvider);

        return [$jwtGuard, $credentials, $user];
    }

    /**
     * @return void
     */
    public function testOnce(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user] = $this->setUpOnceTest();

        $this->assertTrue($jwtGuard->once($credentials));

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
     */
    public function testOnceWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials] = $this->setUpOnceTest(false);

        $this->assertFalse($jwtGuard->once($credentials));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
    }

    /**
     * @return void
     */
    public function testOnceWithoutValidCredentials(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials] = $this->setUpOnceTest(true, false);

        $this->assertFalse($jwtGuard->once($credentials));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
    }

    /**
     * @param bool $withUser
     *
     * @return array
     */
    private function setUpLoginUsingIdTest(bool $withUser = true): array
    {
        $id = $this->getFaker()->numberBetween();
        $user = $this->createUser();
        $userProvider = $this->createUserProviderMock();
        $this->mockUserProviderRetrieveById($userProvider, $withUser ? $user : null, $id);
        $jwtHandler = $this->createJWTHandler();
        [$accessToken, $ttl] = $this->setUpIssueAccessToken($user, $jwtHandler);
        [$refreshToken, $refreshTtl, $refreshTokenRepository] = $this->setUpIssueRefreshToken($user, $jwtHandler);
        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $userProvider,
            $this->createJWTGuardConfig(null, $ttl, $refreshTtl),
            null,
            null,
            null,
            $refreshTokenRepository,
            null,
            null,
            null,
            null,
        );

        return [$jwtGuard, $id, $user, $accessToken, $refreshToken];
    }

    /**
     * @return void
     */
    public function testLoginUsingId(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id, $user, $accessToken] = $this->setUpLoginUsingIdTest();

        $this->assertEquals($user, $jwtGuard->loginUsingId($id));

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
     */
    public function testLoginUsingIdWithRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id, $user, $accessToken, $refreshToken] = $this->setUpLoginUsingIdTest();

        $jwtGuard->loginUsingId($id, true);

        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    /**
     * @return void
     */
    public function testLoginUsingIdWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id] = $this->setUpLoginUsingIdTest(false);

        $this->assertFalse($jwtGuard->loginUsingId($id, true));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    /**
     * @param bool $withUser
     *
     * @return array
     */
    private function setUpOnceUsingIdTest(bool $withUser = true): array
    {
        $id = $this->getFaker()->numberBetween();
        $user = $this->createUser();
        $userProvider = $this->createUserProviderMock();
        $this->mockUserProviderRetrieveById($userProvider, $withUser ? $user : null, $id);
        $jwtGuard = $this->createJWTGuard(null, $userProvider);

        return [$jwtGuard, $id, $user];
    }

    /**
     * @return void
     */
    public function testOnceUsingId(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id, $user] = $this->setUpOnceUsingIdTest();

        $this->assertEquals($user, $jwtGuard->onceUsingId($id));
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    /**
     * @return void
     */
    public function testOnceUsingIdWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id] = $this->setUpOnceUsingIdTest(false);

        $this->assertFalse($jwtGuard->onceUsingId($id));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
    }

    /**
     * @return void
     */
    public function testViaRemember(): void
    {
        $this->assertFalse($this->createJWTGuard()->viaRemember());
    }

    /**
     * @return void
     */
    public function testViaRememberWithRefreshToken(): void
    {
        $jwtGuard = $this->createJWTGuard();
        $this->setPrivateProperty($jwtGuard, 'refreshToken', $this->createJWT());

        $this->assertTrue($jwtGuard->viaRemember());
    }

    //endregion

    /**
     * @param JWTHandler|null             $jwtHandler
     * @param UserProvider|null           $userProvider
     * @param JWTGuardConfig|null         $jwtGuardConfig
     * @param TokenProvider|null          $accessTokenProvider
     * @param TokenBlacklist|null         $tokenBlacklist
     * @param TokenProvider|null          $refreshTokenProvider
     * @param RefreshTokenRepository|null $refreshTokenRepository
     * @param Dispatcher|null             $eventDispatcher
     * @param Request|null                $request
     * @param string|null                 $name
     * @param EventFactory|null           $eventFactory
     *
     * @return JWTGuard|MockInterface
     */
    private function createJWTGuard(
        JWTHandler $jwtHandler = null,
        UserProvider $userProvider = null,
        JWTGuardConfig $jwtGuardConfig = null,
        TokenProvider $accessTokenProvider = null,
        TokenBlacklist $tokenBlacklist = null,
        TokenProvider $refreshTokenProvider = null,
        RefreshTokenRepository $refreshTokenRepository = null,
        Dispatcher $eventDispatcher = null,
        Request $request = null,
        string $name = null,
        EventFactory $eventFactory = null
    ): JWTGuard {
        return new JWTGuard(
            $name ?: $this->getFaker()->word,
            $jwtHandler ?: $this->createJWTHandler(),
            $userProvider ?: $this->createUserProvider(),
            $request ?: $this->createRequest(),
            $jwtGuardConfig ?: $this->createJWTGuardConfig(),
            $accessTokenProvider ?: $this->createAccessTokenProvider(),
            $refreshTokenProvider ?: $this->createRefreshTokenProvider(),
            $refreshTokenRepository ?: $this->createRefreshTokenRepository(),
            $eventFactory ?: $this->createEventFactory(),
            $tokenBlacklist,
            $eventDispatcher,
        );
    }

    /**
     * @param string|null $ipAddress
     *
     * @return Request
     */
    private function createRequestWithIp(string $ipAddress = null): Request
    {
        $request = $this->createRequest();
        $this->mockRequestIp($request, $ipAddress ?: $this->getFaker()->ipv4);

        return $request;
    }

    /**
     * @param JWTHandler|MockInterface $jwtHandler
     * @param JWT|\Exception            $jwt
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
     * @param JWT|\Exception           $jwt
     * @param string                   $subject
     * @param array                    $claims
     * @param int|null                 $ttl
     *
     * @return $this
     */
    private function mockJWTHandlerCreateJWT(
        MockInterface $jwtHandler,
        $jwt,
        string $subject,
        array $claims = [],
        int $ttl = null
    ) {
        $jwtHandler
            ->shouldReceive('createJWT')
            ->with($subject, $claims, $ttl)
            ->andThrow($jwt);

        return $this;
    }

    /**
     * @param JWTHandler|MockInterface $jwtHandler
     * @param JWT|\Exception           $jwt
     * @param string                   $subject
     * @param int|null                 $ttl
     *
     * @return $this
     */
    private function mockJWTHandlerCreateJWTForRefreshToken(
        MockInterface $jwtHandler,
        $jwt,
        string $subject,
        int $ttl = null
    ) {
        $jwtHandler
            ->shouldReceive('createJWT')
            ->with(
                $subject,
                Mockery::on(fn (array $actualClaims) => !empty($actualClaims['rti'])),
                $ttl
            )
            ->andThrow($jwt);

        return $this;
    }

    /**
     * @return UserProvider|MockInterface
     */
    private function createUserProviderMock(): UserProvider
    {
        return Mockery::spy(UserProvider::class);
    }

    /**
     * @param UserProvider|MockInterface $uerProvider
     * @param Authenticatable|null       $user
     * @param array                      $credentials
     *
     * @return $this
     */
    private function mockUserProviderRetrieveByCredentials(
        MockInterface $uerProvider,
        ?Authenticatable $user,
        array $credentials
    ): self {
        $uerProvider
            ->shouldReceive('retrieveByCredentials')
            ->with($credentials)
            ->andReturn($user);

        return $this;
    }

    /**
     * @param UserProvider|MockInterface $userProvider
     * @param bool                       $valid
     * @param Authenticatable            $user
     * @param array                      $credentials
     *
     * @return $this
     */
    private function mockUserProviderValidateCredentials(
        MockInterface $userProvider,
        bool $valid,
        Authenticatable $user,
        array $credentials
    ): self {
        $userProvider
            ->shouldReceive('validateCredentials')
            ->with($user, $credentials)
            ->andReturn($valid);

        return $this;
    }

    /**
     * @param UserProvider|MockInterface $userProvider
     * @param Authenticatable|null       $user
     * @param int                        $id
     *
     * @return $this
     */
    private function mockUserProviderRetrieveById(MockInterface $userProvider, ?Authenticatable $user, int $id): self
    {
        $userProvider
            ->shouldReceive('retrieveById')
            ->with($id)
            ->andReturn($user);

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
    ): JWTAuthenticatable {
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

    /**
     * @return Dispatcher|MockInterface
     */
    private function createEventDispatcher(): Dispatcher
    {
        return Mockery::spy(Dispatcher::class);
    }

    /**
     * @param Dispatcher|MockInterface $eventDispatcher
     * @param mixed                    $event
     *
     * @return $this
     */
    private function assertEventDispatcherDispatch(MockInterface $eventDispatcher, $event): self
    {
        $eventDispatcher
            ->shouldHaveReceived('dispatch')
            ->with($event)
            ->once();

        return $this;
    }

    /**
     * @return Login|MockInterface
     */
    private function createLoginEvent(): Login
    {
        return Mockery::spy(Login::class);
    }

    /**
     * @return Logout|MockInterface
     */
    private function createLogoutEvent(): Logout
    {
        return Mockery::spy(Logout::class);
    }

    /**
     * @return Attempting|MockInterface
     */
    private function createAttemptingEvent(): Attempting
    {
        return Mockery::spy(Attempting::class);
    }

    /**
     * @return Failed|MockInterface
     */
    private function createFailedEvent(): Failed
    {
        return Mockery::spy(Failed::class);
    }
}
