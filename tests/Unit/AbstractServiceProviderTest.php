<?php

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Console\GenerateSecret;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\JWTHandler;
use SPie\LaravelJWT\Providers\AbstractServiceProvider;

/**
 * Class AbstractServiceProviderTest
 */
final class AbstractServiceProviderTest extends TestCase
{

    use TestHelper;
    use JWTHelper;
    use ReflectionMethodHelper;

    //region Tests

    /**
     * @return void
     */
    public function testRegister(): void
    {
        $abstractServiceProvider = $this->createEmptyAbstractServiceProvider();
        $abstractServiceProvider
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $abstractServiceProvider
            ->shouldReceive('registerJWTHandler')
            ->andReturn($abstractServiceProvider);
        $abstractServiceProvider
            ->shouldReceive('registerTokenBlacklist')
            ->andReturn($abstractServiceProvider);
        $abstractServiceProvider
            ->shouldReceive('registerCommands')
            ->andReturn($abstractServiceProvider);

        $this->assertEmpty($abstractServiceProvider->register());

        $abstractServiceProvider
            ->shouldHaveReceived('registerJWTHandler')
            ->once();
        $abstractServiceProvider
            ->shouldHaveReceived('registerTokenBlacklist')
            ->once();
        $abstractServiceProvider
            ->shouldHaveReceived('registerCommands')
            ->once();
    }

    /**
     * @return void
     */
    public function testBoot(): void
    {
        $abstractServiceProvider = $this->createEmptyAbstractServiceProvider();
        $abstractServiceProvider
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $abstractServiceProvider
            ->shouldReceive('extendAuthGuard')
            ->andReturn($abstractServiceProvider);

        $this->assertEmpty($abstractServiceProvider->boot());

        $abstractServiceProvider
            ->shouldHaveReceived('extendAuthGuard')
            ->once();
    }

    /**
     * @return void
     */
    public function testRegisterJWTFactory(): void
    {
        $app = $this->createApp();

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);

        $this->assertEquals(
            $abstractServiceProvider,
            $this->runReflectionMethod($abstractServiceProvider, 'registerJWTFactory')
        );

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                JWTFactoryContract::class,
                JWTFactory::class
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testRegisterJWTHandler(): void
    {
        $signer = Sha256::class;
        $secret = $this->getFaker()->uuid;
        $issuer = $this->getFaker()->uuid;
        $builder = $this->createBuilder();
        $parser = $this->createParser();
        $jwtFactory = $this->createJWTFactory();
        $app = $this->createApp();
        $this->addGet(
            $app,
            null,
            null,
            null,
            null,
            null,
            $builder,
            $parser,
            $jwtFactory
        );

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this
            ->addGetSignerSetting($abstractServiceProvider, $signer)
            ->addGetSecretSetting($abstractServiceProvider, $secret)
            ->addGetIssuerSetting($abstractServiceProvider, $issuer);

        $this->runReflectionMethod($abstractServiceProvider, 'registerJWTHandler');

        $app
            ->shouldHaveReceived('bind')
            ->with(Builder::class)
            ->once();
        $app
            ->shouldHaveReceived('bind')
            ->with(Parser::class)
            ->once();

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                Mockery::on(function (string $abstract) {
                    return ($abstract == JWTHandler::class);
                }),
                Mockery::on(function (\Closure $concrete) use ($signer, $secret, $issuer, $builder, $parser, $jwtFactory) {
                    $expectedJwtHandler = new JWTHandler(
                        $secret,
                        $issuer,
                        $jwtFactory,
                        $builder,
                        $parser,
                        new $signer()
                    );

                    $jwtHandler = $concrete();

                    $this->assertEquals($expectedJwtHandler, $jwtHandler);

                    return ($expectedJwtHandler == $jwtHandler);
                })
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testRegisterTokenBlacklist(): void
    {
        $tokenBlacklistClass = $this->getFaker()->uuid;

        $app = $this->createApp();
        $this->addMake($app, $tokenBlacklistClass);

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this->addGetBlacklistSetting($abstractServiceProvider, $tokenBlacklistClass);

        $this->runReflectionMethod($abstractServiceProvider, 'registerTokenBlacklist');

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                Mockery::on(function (string $abstract) {
                    return ($abstract == TokenBlacklist::class);
                }),
                Mockery::on(function (\Closure $concrete) use ($tokenBlacklistClass) {
                    $tokenBlacklist = $concrete();

                    return ($tokenBlacklist == $tokenBlacklistClass);
                })
            )
            ->once();

        $this->assertTrue(true);
    }

    /**
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testRegisterTokenBlacklistWithoutBlacklistSetting(): void
    {
        $app = $this->createApp();

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this->addGetBlacklistSetting($abstractServiceProvider);

        $this->runReflectionMethod($abstractServiceProvider, 'registerTokenBlacklist');

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                TokenBlacklist::class,
                Mockery::on(function (\Closure $concrete) {
                    $tokenBlacklist = $concrete();

                    return \is_null($tokenBlacklist);
                })
            )
            ->once();

        $app->shouldNotHaveReceived('make');

        $this->assertTrue(true);
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testRegisterCommands(): void
    {
        $abstractServiceProvider = $this->createAbstractServiceProvider();

        $this->runReflectionMethod($abstractServiceProvider, 'registerCommands');

        $abstractServiceProvider
            ->shouldHaveReceived('commands')
            ->with([GenerateSecret::class])
            ->atLeast()
            ->once();

        $this->assertTrue(true);
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testExtendAuthGuard(): void
    {
        $userProvider = Mockery::mock(UserProvider::class);
        $request = new Request();
        $jwtHandler = Mockery::mock(JWTHandler::class);
        $tokenBlacklist = Mockery::mock(TokenBlacklist::class);
        $refreshTokenRepository = Mockery::mock(RefreshTokenRepository::class);

        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn($userProvider);

        $app = $this->createApp();
        $this->addGet(
            $app,
            $authManager,
            $tokenBlacklist,
            $request,
            $jwtHandler,
            $refreshTokenRepository
        );

        $accessTokenProviderKey = $this->getFaker()->uuid;
        $refreshTokenProviderKey = $this->getFaker()->uuid;
        $accessTokenTTL = $this->getFaker()->numberBetween();
        $refreshTokenTTL = $this->getFaker()->numberBetween();

        $jwtGuard = new JWTGuard(
            $jwtHandler,
            $userProvider,
            $request,
            (new TestTokenProvider())->setKey($accessTokenProviderKey),
            $accessTokenTTL,
            $tokenBlacklist,
            (new TestTokenProvider())->setKey($refreshTokenProviderKey),
            $refreshTokenTTL,
            $refreshTokenRepository
        );

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this
            ->addGetAccessTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetAccessTokenProviderKeySetting($abstractServiceProvider, $accessTokenProviderKey)
            ->addGetRefreshTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetRefreshTokenProviderKeySetting($abstractServiceProvider, $refreshTokenProviderKey)
            ->addGetAccessTokenTTLSetting($abstractServiceProvider, $accessTokenTTL)
            ->addGetRefreshTokenTTLSetting($abstractServiceProvider, $refreshTokenTTL)
            ->addGetRefreshTokenRepositoryClass($abstractServiceProvider, RefreshTokenRepository::class);

        $this->runReflectionMethod($abstractServiceProvider, 'extendAuthGuard');

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::on(function (\Closure $concrete) use ($app, $jwtGuard) {
                    $concreteJwtGuard = $concrete(
                        $app,
                        $this->getFaker()->uuid,
                        [
                            'provider' => Mockery::mock(UserProvider::class),
                        ]
                    );
                    $this->assertEquals($jwtGuard, $concreteJwtGuard);

                    return ($jwtGuard == $concreteJwtGuard);
                })
            )
            ->once();

        $app
            ->shouldHaveReceived('refresh')
            ->with(
                'request',
                Mockery::any(),
                'setRequest'
            )
            ->atLeast()
            ->once();

        $this->assertTrue(true);
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testExtendAuthGuardOnlyWithRequiredProperties(): void
    {
        $request = new Request();
        $jwtHandler = Mockery::mock(JWTHandler::class);

        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn(Mockery::mock(UserProvider::class));

        $app = $this->createApp();
        $this->addGet(
            $app,
            $authManager,
            null,
            $request,
            $jwtHandler
        );

        $accessTokenProviderKey = $this->getFaker()->uuid;
        $accessTokenTTL = $this->getFaker()->numberBetween();

        $jwtGuard = new JWTGuard(
            $jwtHandler,
            Mockery::mock(UserProvider::class),
            $request,
            (new TestTokenProvider())->setKey($accessTokenProviderKey),
            $accessTokenTTL
        );

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this
            ->addGetAccessTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetAccessTokenProviderKeySetting($abstractServiceProvider, $accessTokenProviderKey)
            ->addGetAccessTokenTTLSetting($abstractServiceProvider, $accessTokenTTL)
            ->addGetRefreshTokenProviderClassSetting($abstractServiceProvider, null)
            ->addGetRefreshTokenProviderKeySetting($abstractServiceProvider, null)
            ->addGetRefreshTokenTTLSetting($abstractServiceProvider, null)
            ->addGetRefreshTokenRepositoryClass($abstractServiceProvider, null);

        $this->runReflectionMethod($abstractServiceProvider, 'extendAuthGuard');

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::on(function (\Closure $concrete) use ($app, $jwtGuard) {
                    $concreteJwtGuard = $concrete(
                        $app,
                        $this->getFaker()->uuid,
                        [
                            'provider' => Mockery::mock(UserProvider::class),
                        ]
                    );

                    return ($jwtGuard == $concreteJwtGuard);
                })
            )
            ->once();

        $app
            ->shouldHaveReceived('refresh')
            ->with(
                'request',
                Mockery::any(),
                'setRequest'
            )
            ->atLeast()
            ->once();

        $this->assertTrue(true);
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testGetAccessTokenProvider(): void
    {
        $key = $this->getFaker()->uuid;

        $abstractServiceProvider = $this->createAbstractServiceProvider();
        $this
            ->addGetAccessTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetAccessTokenProviderKeySetting($abstractServiceProvider, $key);

        $tokenProvider = $this->runReflectionMethod($abstractServiceProvider, 'getAccessTokenProvider');

        $this->assertInstanceOf(TokenProvider::class, $tokenProvider);
        $this->assertEquals($key, $tokenProvider->getKey());
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testGetRefreshTokenProvider(): void
    {
        $key = $this->getFaker()->uuid;

        $abstractServiceProvider = $this->createAbstractServiceProvider();
        $this
            ->addGetRefreshTokenProviderClassSetting(
                $abstractServiceProvider,
                TestTokenProvider::class
            )
            ->addGetRefreshTokenProviderKeySetting($abstractServiceProvider, $key);

        $tokenProvider = $this->runReflectionMethod($abstractServiceProvider, 'getRefreshTokenProvider');

        $this->assertInstanceOf(TokenProvider::class, $tokenProvider);
        $this->assertEquals($key, $tokenProvider->getKey());
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testGetRefreshTokenProviderWithoutTokenProvider(): void
    {
        $abstractServiceProvider = $this->createAbstractServiceProvider();
        $this
            ->addGetRefreshTokenProviderClassSetting(
                $abstractServiceProvider,
                null
            )
            ->addGetRefreshTokenProviderKeySetting($abstractServiceProvider, null);

        $this->assertEmpty(
            $this->runReflectionMethod($abstractServiceProvider, 'getRefreshTokenProvider')
        );
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testGetRefreshTokenProviderWithoutKey(): void
    {
        $abstractServiceProvider = $this->createAbstractServiceProvider();
        $this
            ->addGetRefreshTokenProviderClassSetting(
                $abstractServiceProvider,
                TestTokenProvider::class
            )
            ->addGetRefreshTokenProviderKeySetting($abstractServiceProvider, null);


        $this->expectException(InvalidTokenProviderKeyException::class);

        $this->runReflectionMethod($abstractServiceProvider, 'getRefreshTokenProvider');
    }

    //endregion

    /**
     * @param Application|null $app
     *
     * @return AbstractServiceProvider|MockInterface
     */
    private function createAbstractServiceProvider(Application $app = null): AbstractServiceProvider
    {
        $abstractServiceProvider = Mockery::spy(AbstractServiceProvider::class, [$app]);
        $abstractServiceProvider->makePartial();
        $abstractServiceProvider->shouldAllowMockingProtectedMethods();

        return $abstractServiceProvider;
    }

    /**
     * @return AbstractServiceProvider|MockInterface
     */
    private function createEmptyAbstractServiceProvider(): AbstractServiceProvider
    {
        return Mockery::spy(AbstractServiceProvider::class);
    }

    /**
     * @return Application|MockInterface
     */
    private function createApp(): Application
    {
        return Mockery::spy(Application::class);
    }

    /**
     * @param Application|MockInterface   $app
     * @param AuthManager|null            $authManager
     * @param TokenBlacklist|null         $withTokenBlacklist
     * @param Request|null                $request
     * @param JWTHandler|null             $jwtHandler
     * @param RefreshTokenRepository|null $refreshTokenRepository
     * @param Builder|null                $builder
     * @param Parser|null                 $parser
     * @param JWTFactoryContract|null     $jwtFactory
     *
     * @return AbstractServiceProviderTest
     */
    private function addGet(
        Application $app,
        AuthManager $authManager = null,
        TokenBlacklist $withTokenBlacklist = null,
        Request $request = null,
        JWTHandler $jwtHandler = null,
        RefreshTokenRepository $refreshTokenRepository = null,
        Builder $builder = null,
        Parser $parser = null,
        JWTFactoryContract $jwtFactory = null
    ): AbstractServiceProviderTest
    {
        $app
            ->shouldReceive('get')
            ->andReturnUsing(
                function (string $argument)
                use (
                    $authManager,
                    $withTokenBlacklist,
                    $request,
                    $jwtHandler,
                    $refreshTokenRepository,
                    $builder,
                    $parser,
                    $jwtFactory
                ) {
                    switch ($argument) {
                        case 'auth':
                            return $authManager;

                        case JWTHandler::class:
                            return $jwtHandler ?: Mockery::mock(JWTHandler::class);

                        case 'request':
                            return $request ?: new Request();

                        case TokenBlacklist::class:
                            return $withTokenBlacklist;

                        case RefreshTokenRepository::class:
                            return $refreshTokenRepository;

                        case Builder::class:
                            return $builder;

                        case Parser::class:
                            return $parser;

                        case JWTFactoryContract::class:
                            return $jwtFactory;

                        default:
                            return $this->getFaker()->uuid;
                    }
                }
            );

        return $this;
    }

    /**
     * @param Application|MockInterface $app
     * @param mixed|null                $concrete
     *
     * @return AbstractServiceProviderTest
     */
    private function addMake(Application $app, $concrete = null): AbstractServiceProviderTest
    {
        $app
            ->shouldReceive('make')
            ->andReturn($concrete);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $secret
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetSecretSetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $secret = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getSecretSetting')
            ->andReturn($secret);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $issuer
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetIssuerSetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $issuer = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getIssuerSetting')
            ->andReturn($issuer);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param int|null                              $ttl
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetAccessTokenTTLSetting(
        AbstractServiceProvider $abstractServiceProvider,
        int $ttl = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getAccessTokenTTLSetting')
            ->andReturn($ttl);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param int|null                              $ttl
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetRefreshTokenTTLSetting(
        AbstractServiceProvider $abstractServiceProvider,
        int $ttl = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getRefreshTokenTTLSetting')
            ->andReturn($ttl);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $refreshTokenRepositoryClass
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetRefreshTokenRepositoryClass(
        AbstractServiceProvider $abstractServiceProvider,
        string $refreshTokenRepositoryClass = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getRefreshTokenRepositoryClass')
            ->andReturn($refreshTokenRepositoryClass);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $signer
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetSignerSetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $signer= null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getSignerSetting')
            ->andReturn($signer);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $tokenProviderClass
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetAccessTokenProviderClassSetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $tokenProviderClass = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getAccessTokenProviderClassSetting')
            ->andReturn($tokenProviderClass);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $tokenProviderKey
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetAccessTokenProviderKeySetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $tokenProviderKey = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getAccessTokenProviderKeySetting')
            ->andReturn($tokenProviderKey);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $blacklist
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetBlacklistSetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $blacklist = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getBlacklistSetting')
            ->andReturn($blacklist);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $refreshTokenProviderClass
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetRefreshTokenProviderClassSetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $refreshTokenProviderClass = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getRefreshTokenProviderClassSetting')
            ->andReturn($refreshTokenProviderClass);

        return $this;
    }

    /**
     * @param AbstractServiceProvider|MockInterface $abstractServiceProvider
     * @param string|null                           $refreshTokenProviderKey
     *
     * @return AbstractServiceProviderTest
     */
    private function addGetRefreshTokenProviderKeySetting(
        AbstractServiceProvider $abstractServiceProvider,
        string $refreshTokenProviderKey = null
    ): AbstractServiceProviderTest
    {
       $abstractServiceProvider
           ->shouldReceive('getRefreshTokenProviderKeySetting')
           ->andReturn($refreshTokenProviderKey);

        return $this;
    }
}
