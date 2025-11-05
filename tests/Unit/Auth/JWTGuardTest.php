<?php

namespace SPie\LaravelJWT\Test\Unit\Auth;

use Illuminate\Auth\AuthenticationException;
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
use SPie\LaravelJWT\Contracts\TokenBlockList;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Contracts\JWTHandler;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\RequestHelper;
use SPie\LaravelJWT\Test\TestHelper;
use Symfony\Component\HttpFoundation\Response;

final class JWTGuardTest extends TestCase
{
    use HttpHelper;
    use JWTHelper;
    use ReflectionMethodHelper;
    use RequestHelper;
    use TestHelper;

    /**
     * @return JWTGuard|MockInterface
     */
    private function createJWTGuard(
        ?JWTHandler $jwtHandler = null,
        ?UserProvider $userProvider = null,
        ?JWTGuardConfig $jwtGuardConfig = null,
        ?TokenProvider $accessTokenProvider = null,
        ?TokenBlockList $tokenBlockList = null,
        ?TokenProvider $refreshTokenProvider = null,
        ?RefreshTokenRepository $refreshTokenRepository = null,
        ?Dispatcher $eventDispatcher = null,
        ?Request $request = null,
        ?string $name = null,
        ?EventFactory $eventFactory = null
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
            $tokenBlockList,
            $eventDispatcher,
        );
    }

    private function createRequestWithIp(?string $ipAddress = null): Request
    {
        $request = $this->createRequest();
        $this->mockRequestIp($request, $ipAddress ?: $this->getFaker()->ipv4);

        return $request;
    }

    private function addGetValidJWT(MockInterface $jwtHandler, $jwt): JWTGuardTest
    {
        $getValidJWTExpectation = $jwtHandler->shouldReceive('getValidJWT');

        if ($jwt instanceof \Exception) {
            $getValidJWTExpectation->andThrow($jwt);

            return $this;
        }

        $getValidJWTExpectation->andReturn($jwt);

        return $this;
    }

    private function mockJWTHandlerCreateJWT(
        MockInterface $jwtHandler,
        $jwt,
        string $subject,
        array $claims = [],
        ?int $ttl = null
    ) {
        $jwtHandler
            ->shouldReceive('createJWT')
            ->with($subject, $claims, $ttl)
            ->andThrow($jwt);

        return $this;
    }

    private function mockJWTHandlerCreateJWTForRefreshToken(
        MockInterface $jwtHandler,
        $jwt,
        string $subject,
        ?int $ttl = null
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

    private function mockUserProviderRetrieveById(MockInterface $userProvider, ?Authenticatable $user, string $id): self
    {
        $userProvider
            ->shouldReceive('retrieveById')
            ->with($id)
            ->andReturn($user);

        return $this;
    }

    /**
     * @return UserProvider|MockInterface
     */
    private function createUserProvider(?Authenticatable $user = null, bool $validCredentials = false): UserProvider
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
     * @return JWTAuthenticatable|MockInterface
     */
    private function createUser(
        ?string $authIdentifierName = null,
        ?string $authIdentifier = null,
        ?string $authPassword = null,
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
     * @return TokenProvider|MockInterface
     */
    private function createAccessTokenProvider(?string $token = null, ?Response $response = null): TokenProvider
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
     * @return TokenProvider|MockInterface
     */
    private function createRefreshTokenProvider(?string $token = null, ?Response $response = null): TokenProvider
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

    private function assertTokenProviderSetResponseToken(
        MockInterface $tokenProvider,
        Response $response,
        string $token
    ): self {
        $tokenProvider
            ->shouldHaveReceived('setResponseToken')
            ->with($response, $token)
            ->once();

        return $this;
    }

    /**
     * @return TokenBlockList|MockInterface
     */
    private function createTokenBlockList(): TokenBlockList
    {
        return Mockery::spy(TokenBlockList::class);
    }

    private function mockTokenBlockListIsRevoked(MockInterface $tokenBlockList, bool $isRevoked, string $token): self
    {
        $tokenBlockList
            ->shouldReceive('isRevoked')
            ->with($token)
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

    private function setUpUserTest(
        bool $withUser = false,
        bool $withAccessToken = true,
        bool $withRefreshToken = true,
        bool $withValidAccessToken = true,
        bool $withValidRefreshToken = true,
        bool $withUserFound = true,
        bool $withBlockedAccessToken = false,
        bool $withRevokedRefreshToken = false,
        bool $withValidIpAddress = true,
        bool $withIpCheck = false
    ): array {
        $user = $this->createUser();
        $request = $this->createRequest();
        $this->mockRequestIp($request, $this->getFaker()->ipv4);
        $accessToken = $this->getFaker()->sha256;
        $accessTokenProvider = $this->createTokenProvider();
        $this->mockTokenProviderGetRequestToken($accessTokenProvider, $withAccessToken ? $accessToken : null, $request);
        $accessJwt = $this->createJWT();
        $this
            ->mockJWTGetSubject($accessJwt, $user->getAuthIdentifier())
            ->mockJWTGetIpAddress($accessJwt, ($withValidIpAddress ? '' : '1') . $request->ip());
        $refreshToken = $this->getFaker()->sha256;
        $refreshTokenProvider = $this->createTokenProvider();
        $this->mockTokenProviderGetRequestToken($refreshTokenProvider, $withRefreshToken ? $refreshToken : null, $request);
        $refreshJwt = $this->createJWT();
        $this
            ->mockJWTGetSubject($refreshJwt, $user->getAuthIdentifier())
            ->mockJWTGetIpAddress($refreshJwt, ($withValidIpAddress ? '' : '1') . $request->ip())
            ->mockJWTGetRefreshTokenId($refreshJwt, $this->getFaker()->word);
        $ttl = $this->getFaker()->numberBetween();
        $jwtHandler = $this->createJWTHandler();
        $this
            ->mockJWTHandlerGetValidJWT($jwtHandler, $withValidAccessToken ? $accessJwt : new InvalidTokenException(), $accessToken)
            ->mockJWTHandlerGetValidJWT($jwtHandler, $withValidRefreshToken ? $refreshJwt : new InvalidTokenException(), $refreshToken)
            ->mockJWTHandlerCreateJWT(
                $jwtHandler,
                $accessJwt,
                $user->getAuthIdentifier(),
                \array_merge($user->getCustomClaims(), ['ipa' => $request->ip()]),
                $ttl
            );
        $userProvider = $this->createUserProviderMock();
        $this->mockUserProviderRetrieveById($userProvider, $withUserFound ? $user : null, $accessJwt->getSubject());
        $tokenBlockList = $this->createTokenBlockList();
        $this->mockTokenBlockListIsRevoked($tokenBlockList, $withBlockedAccessToken, $accessToken);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $this->mockRefreshTokenRepositoryIsRefreshTokenRevoked($refreshTokenRepository, $withRevokedRefreshToken, $refreshJwt->getRefreshTokenId());
        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            $userProvider,
            $this->createJWTGuardConfig($withIpCheck, $ttl),
            $accessTokenProvider,
            $tokenBlockList,
            $refreshTokenProvider,
            $refreshTokenRepository,
            null,
            $request
        );
        if ($withUser) {
            $this->setPrivateProperty($jwtGuard, 'user', $user);
        }

        return [$jwtGuard, $user, $accessJwt, $refreshJwt];
    }

    public function testUserWithAlreadyAuthenticatedUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user] = $this->setUpUserTest(true);

        $this->assertEquals($jwtGuard->user(), $user);
    }

    public function testUserWithValidAccessAndRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user, $accessToken, $refreshToken] = $this->setUpUserTest();

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithValidAccessAndRefreshTokenWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            true,
            true,
            true,
            true,
            false
        );

        $this->assertNull($jwtGuard->user());
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithoutAccessToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(false, false, false);

        $this->assertNull($jwtGuard->user());
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    public function testUserWithoutRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user, $accessToken] = $this->setUpUserTest(false, true, false);

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithInvalidAccessTokenAndWithoutRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(false, true, false, false);

        $this->assertNull($jwtGuard->user());
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    public function testUserWithoutAccessTokenAndValidRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user, $accessToken, $refreshToken] = $this->setUpUserTest(
            false,
            false,
            true
        );

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithInvalidAccessTokenAndValidRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user, $accessToken, $refreshToken] = $this->setUpUserTest(
            false,
            true,
            true,
            false
        );

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithInvalidAccessTokenAndInvalidRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            true,
            true,
            false,
            false
        );

        $this->assertNull($jwtGuard->user());
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithInvalidAccessTokenAndValidRefreshTokenAndNoUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            true,
            true,
            false,
            true,
            false
        );

        $this->assertNull($jwtGuard->user());
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertNull($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testUserWithBlockedAccessToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            true,
            false,
            true,
            false,
            true,
            true
        );

        $this->assertNull($jwtGuard->user());
    }

    public function testUserWithWithRevokedRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            false,
            true,
            false,
            true,
            true,
            false,
            true
        );

        $this->assertNull($jwtGuard->user());
    }

    public function testUserWithWithInvalidIp(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true
        );

        $this->assertNull($jwtGuard->user());
    }

    public function testUserWithWithInvalidIpWithoutIpCheck(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user] = $this->setUpUserTest(
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false
        );

        $this->assertEquals($user, $jwtGuard->user());
    }

    public function testUserWithWithInvalidIpOnRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard] = $this->setUpUserTest(
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true
        );

        $this->assertNull($jwtGuard->user());
    }

    public function testUserWithWithInvalidIpWithoutIpCheckOnRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $user] = $this->setUpUserTest(
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false
        );

        $this->assertEquals($user, $jwtGuard->user());
    }

    public function testValidate(): void
    {
        $this->assertTrue(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser(), true)
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    public function testValidateWithoutUser(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider()
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    public function testValidateWithInvalidCredentials(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser())
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    private function setUpIssueAccessToken(JWTAuthenticatable $user, JWTHandler $jwtHandler, ?string $ipAddress = null): array
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

    private function setUpIssueRefreshToken(JWTAuthenticatable $user, JWTHandler $jwtHandler, ?string $ipAddress = null): array
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

    public function testLoginWithIpAddress(): void
    {
        /** @var JWTGuard   $jwtGuard */
        [$jwtGuard, $user, $accessToken] = $this->setUpLoginTest(true);

        $jwtGuard->login($user);

        $this->assertEquals($accessToken, $jwtGuard->getAccessToken());
    }

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

    public function testLogout(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $tokenBlockList = $this->createTokenBlockList();
        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            $tokenBlockList
        );
        $this
            ->setPrivateProperty($jwtGuard, 'accessToken', $jwt)
            ->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $tokenBlockList
            ->shouldHaveReceived('revoke')
            ->with($jwt)
            ->once();
    }

    public function testLogoutWithoutTokenBlockList(): void
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

    public function testLogoutWithoutJWT(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $tokenBlockList = $this->createTokenBlockList();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            null,
            $tokenBlockList
        );
        $this->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
        $tokenBlockList->shouldNotHaveReceived('revoke');
    }

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
            $this->createTokenBlockList(),
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

    public function testLogoutWithoutRefreshToken(): void
    {
        $jwt = $this->createJWT();
        $jwtHandler = $this->createJWTHandler();
        $this->addGetValidJWT($jwtHandler, $jwt);
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $tokenBlockList = $this->createTokenBlockList();

        $jwtGuard = $this->createJWTGuard(
            $jwtHandler,
            null,
            null,
            $this->createAccessTokenProvider(),
            $tokenBlockList,
            null,
            $refreshTokenRepository
        );
        $this
            ->setPrivateProperty($jwtGuard, 'accessToken', $jwt)
            ->setPrivateProperty($jwtGuard, 'user', $this->createUser());

        $jwtGuard->logout();

        $refreshTokenRepository->shouldNotHaveReceived('revokeRefreshToken');
    }

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

    public function testLogoutWithoutAuthenticatedUser(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->createJWTGuard()->logout();
    }

    private function setUpReturnTokensTest(bool $withAccessToken = true, bool $withRefreshToken = true): array
    {
        $response = $this->createEmptyResponse();
        $accessToken = $this->createJWT();
        $this->mockJWTGetJWT($accessToken, $this->getFaker()->sha256);
        $refreshToken = $this->createJWT();
        $this->mockJWTGetJWT($refreshToken, $this->getFaker()->sha256);
        $accessTokenProvider = $this->createAccessTokenProvider(null, $response);
        $refreshTokenProvider = $this->createRefreshTokenProvider(null, $response);
        $jwtGuard = $this->createJWTGuard(
            null,
            null,
            null,
            $accessTokenProvider,
            null,
            $refreshTokenProvider,
        );
        if ($withAccessToken) {
            $this->setPrivateProperty($jwtGuard, 'accessToken', $accessToken);
        }
        if ($withRefreshToken) {
            $this->setPrivateProperty($jwtGuard, 'refreshToken', $refreshToken);
        }

        return [$jwtGuard, $response, $accessTokenProvider, $refreshTokenProvider, $accessToken, $refreshToken];
    }

    public function testReturnTokensWithBothTokens(): void
    {
        /**
         * @var JWTGuard                    $jwtGuard
         * @var Response                    $response
         * @var TokenProvider|MockInterface $accessTokenProvider
         * @var TokenProvider|MockInterface $refreshTokenProvider
         */
        [
            $jwtGuard,
            $response,
            $accessTokenProvider,
            $refreshTokenProvider,
            $accessToken,
            $refreshToken
        ] = $this->setUpReturnTokensTest();

        $this->assertEquals($response, $jwtGuard->returnTokens($response));
        $this
            ->assertTokenProviderSetResponseToken($accessTokenProvider, $response, $accessToken->getJWT())
            ->assertTokenProviderSetResponseToken($refreshTokenProvider, $response, $refreshToken->getJWT());
    }

    public function testReturnTokensWithoutAccessToken(): void
    {
        /**
         * @var JWTGuard                    $jwtGuard
         * @var Response                    $response
         * @var TokenProvider|MockInterface $accessTokenProvider
         * @var TokenProvider|MockInterface $refreshTokenProvider
         */
        [
            $jwtGuard,
            $response,
            $accessTokenProvider,
            $refreshTokenProvider,
            $accessToken,
            $refreshToken,
        ] = $this->setUpReturnTokensTest(false);

        $this->assertEquals($response, $jwtGuard->returnTokens($response));
        $this->assertTokenProviderSetResponseToken($refreshTokenProvider, $response, $refreshToken->getJWT());
        $accessTokenProvider->shouldNotHaveReceived('setResponseToken');
    }

    public function testReturnTokensWithoutRefreshToken(): void
    {
        /**
         * @var JWTGuard                    $jwtGuard
         * @var Response                    $response
         * @var TokenProvider|MockInterface $accessTokenProvider
         * @var TokenProvider|MockInterface $refreshTokenProvider
         */
        [
            $jwtGuard,
            $response,
            $accessTokenProvider,
            $refreshTokenProvider,
            $accessToken,
        ] = $this->setUpReturnTokensTest(true, false);

        $this->assertEquals($response, $jwtGuard->returnTokens($response));
        $this->assertTokenProviderSetResponseToken($accessTokenProvider, $response, $accessToken->getJWT());
        $refreshTokenProvider->shouldNotHaveReceived('setResponseToken');
    }

    public function testReturnTokensWithoutTokens(): void
    {
        /**
         * @var JWTGuard                    $jwtGuard
         * @var Response                    $response
         * @var TokenProvider|MockInterface $accessTokenProvider
         * @var TokenProvider|MockInterface $refreshTokenProvider
         */
        [
            $jwtGuard,
            $response,
            $accessTokenProvider,
            $refreshTokenProvider,
        ] = $this->setUpReturnTokensTest(false, false);

        $this->assertEquals($response, $jwtGuard->returnTokens($response));
        $accessTokenProvider->shouldNotHaveReceived('setResponseToken');
        $refreshTokenProvider->shouldNotHaveReceived('setResponseToken');
    }

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

    public function testAttempt(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user, $accessToken] = $this->setUpAttemptTest();

        $this->assertTrue($jwtGuard->attempt($credentials));

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    public function testAttemptWithRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user, $accessToken, $refreshToken] = $this->setUpAttemptTest(true);

        $this->assertTrue($jwtGuard->attempt($credentials, true));

        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

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

    public function testAttemptWithEvents(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user, $accessToken, $refreshToken, $eventDispatcher, $attemptingEvent] = $this->setUpAttemptTest();

        $jwtGuard->attempt($credentials);

        $this->assertEventDispatcherDispatch($eventDispatcher, $attemptingEvent);
    }

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

    public function testOnce(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials, $user] = $this->setUpOnceTest();

        $this->assertTrue($jwtGuard->once($credentials));

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    public function testOnceWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials] = $this->setUpOnceTest(false);

        $this->assertFalse($jwtGuard->once($credentials));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
    }

    public function testOnceWithoutValidCredentials(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $credentials] = $this->setUpOnceTest(true, false);

        $this->assertFalse($jwtGuard->once($credentials));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
    }

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

    public function testLoginUsingId(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id, $user, $accessToken] = $this->setUpLoginUsingIdTest();

        $this->assertEquals($user, $jwtGuard->loginUsingId($id));

        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEquals($accessToken, $this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    public function testLoginUsingIdWithRefreshToken(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id, $user, $accessToken, $refreshToken] = $this->setUpLoginUsingIdTest();

        $jwtGuard->loginUsingId($id, true);

        $this->assertEquals($refreshToken, $this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    public function testLoginUsingIdWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id] = $this->setUpLoginUsingIdTest(false);

        $this->assertFalse($jwtGuard->loginUsingId($id, true));

        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'refreshToken'));
    }

    private function setUpOnceUsingIdTest(bool $withUser = true): array
    {
        $id = $this->getFaker()->numberBetween();
        $user = $this->createUser();
        $userProvider = $this->createUserProviderMock();
        $this->mockUserProviderRetrieveById($userProvider, $withUser ? $user : null, $id);
        $jwtGuard = $this->createJWTGuard(null, $userProvider);

        return [$jwtGuard, $id, $user];
    }

    public function testOnceUsingId(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id, $user] = $this->setUpOnceUsingIdTest();

        $this->assertEquals($user, $jwtGuard->onceUsingId($id));
        $this->assertEquals($user, $this->getPrivateProperty($jwtGuard, 'user'));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'accessToken'));
    }

    public function testOnceUsingIdWithoutUser(): void
    {
        /** @var JWTGuard $jwtGuard */
        [$jwtGuard, $id] = $this->setUpOnceUsingIdTest(false);

        $this->assertFalse($jwtGuard->onceUsingId($id));
        $this->assertEmpty($this->getPrivateProperty($jwtGuard, 'user'));
    }

    public function testViaRemember(): void
    {
        $this->assertFalse($this->createJWTGuard()->viaRemember());
    }

    public function testViaRememberWithRefreshToken(): void
    {
        $jwtGuard = $this->createJWTGuard();
        $this->setPrivateProperty($jwtGuard, 'refreshToken', $this->createJWT());

        $this->assertTrue($jwtGuard->viaRemember());
    }
}
