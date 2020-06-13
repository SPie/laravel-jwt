<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\JWTHandler;
use SPie\LaravelJWT\Providers\Registrar;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\TestHelper;
use SPie\LaravelJWT\Test\TestSigner;
use SPie\LaravelJWT\Test\TestTokenProvider;

/**
 * Class Registrar
 */
final class RegistrarTest extends TestCase
{
    use TestHelper;
    use JWTHelper;
    use ReflectionMethodHelper;

    //region Tests

    /**
     * @return void
     */
    public function testRegisterJWTFactory(): void
    {
        $app = $this->createApp();

        $registrar = $this->createRegistrar($app);

        $this->assertEquals(
            $registrar,
            $this->runReflectionMethod($registrar, 'registerJWTFactory')
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
     */
    public function testRegisterJWTHandler(): void
    {
        $secret = $this->getFaker()->uuid;
        $issuer = $this->getFaker()->uuid;
        $builder = $this->createBuilder();
        $parser = $this->createParser();
        $jwtFactory = $this->createJWTFactory();
        $app = $this->createApp();
        $this
            ->addGet(
                $app,
                null,
                null,
                null,
                null,
                null,
                null,
                $builder,
                $parser,
                $jwtFactory,
                [
                    'jwt.signer' => TestSigner::class,
                    'jwt.secret' => $secret,
                    'jwt.issuer' => $issuer,
                ]
            );

        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'registerJWTHandler');

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
                    return ($abstract == JWTHandlerContract::class);
                }),
                Mockery::on(function (\Closure $concrete) use ($secret, $issuer, $builder, $parser, $jwtFactory) {
                    $expectedJwtHandler = new JWTHandler(
                        $secret,
                        $issuer,
                        $jwtFactory,
                        $builder,
                        $parser,
                        new TestSigner()
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
     */
    public function testRegisterTokenBlacklist(): void
    {
        $tokenBlacklistClass = $this->getFaker()->uuid;

        $app = $this->createApp();
        $this
            ->addGetConfig(
                $app,
                [
                    'jwt.tokenBlacklist' => $tokenBlacklistClass
                ]
            )
            ->addMake($app, $tokenBlacklistClass);

        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'registerTokenBlacklist');

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
     */
    public function testRegisterTokenBlacklistWithoutBlacklistSetting(): void
    {
        $app = $this->createApp();
        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'registerTokenBlacklist');

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
     */
    public function testExtendAuthGuard(): void
    {
        $guardName = $this->getFaker()->word;
        $userProvider = Mockery::mock(UserProvider::class);
        $request = new Request();
        $eventDispatcher = Mockery::mock(Dispatcher::class);
        $jwtHandler = Mockery::mock(JWTHandlerContract::class);
        $tokenBlacklist = Mockery::mock(TokenBlacklist::class);
        $refreshTokenRepository = Mockery::mock(RefreshTokenRepository::class);

        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn($userProvider);

        $eventFactory = $this->createEventFactory();
        $accessTokenProviderKey = $this->getFaker()->uuid;
        $refreshTokenProviderKey = $this->getFaker()->uuid;
        $accessTokenTTL = $this->getFaker()->numberBetween();
        $refreshTokenTTL = $this->getFaker()->numberBetween();
        $ipCheckEnabled = $this->getFaker()->boolean;

        $app = $this->createApp();
        $this->addGet(
            $app,
            $authManager,
            $tokenBlacklist,
            $request,
            $eventDispatcher,
            $jwtHandler,
            $refreshTokenRepository,
            null,
            null,
            null,
            [
                'jwt.accessTokenProvider.class'  => TestTokenProvider::class,
                'jwt.accessTokenProvider.key'    => $accessTokenProviderKey,
                'jwt.accessTokenProvider.ttl'    => $accessTokenTTL,
                'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
                'jwt.refreshTokenProvider.key'   => $refreshTokenProviderKey,
                'jwt.refreshTokenProvider.ttl'   => $refreshTokenTTL,
                'jwt.refreshTokenRepository'     => RefreshTokenRepository::class,
                'jwt.ipCheckEnabled'             => $ipCheckEnabled,
            ],
            $eventFactory
        );

        $jwtGuard = new JWTGuard(
            $guardName,
            $jwtHandler,
            $userProvider,
            $request,
            (new TestTokenProvider())->setKey($accessTokenProviderKey),
            $accessTokenTTL,
            (new TestTokenProvider())->setKey($refreshTokenProviderKey),
            $refreshTokenRepository,
            $eventFactory,
            $tokenBlacklist,
            $refreshTokenTTL,
            $eventDispatcher,
            $ipCheckEnabled
        );

        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'extendAuthGuard');

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::on(function (\Closure $concrete) use ($app, $jwtGuard, $guardName) {
                    $concreteJwtGuard = $concrete(
                        $app,
                        $guardName,
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
     */
    public function testExtendAuthGuardOnlyWithRequiredProperties(): void
    {
        $guardName = $this->getFaker()->word;
        $userProvider = Mockery::mock(UserProvider::class);
        $request = new Request();
        $jwtHandler = Mockery::mock(JWTHandlerContract::class);

        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn($userProvider);

        $accessTokenProviderKey = $this->getFaker()->uuid;
        $accessTokenTTL = $this->getFaker()->numberBetween();
        $eventFactory = $this->createEventFactory();
        $refreshTokenProviderKey = $this->getFaker()->word;
        $refreshTokenRepository = $this->createRefreshTokenRepository();

        $app = $this->createApp();
        $this->addGet(
            $app,
            $authManager,
            null,
            $request,
            null,
            $jwtHandler,
            $refreshTokenRepository,
            null,
            null,
            null,
            [
                'jwt.accessTokenProvider.class'  => TestTokenProvider::class,
                'jwt.accessTokenProvider.key'    => $accessTokenProviderKey,
                'jwt.accessTokenProvider.ttl'    => $accessTokenTTL,
                'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
                'jwt.refreshTokenProvider.key'   => $refreshTokenProviderKey,
                'jwt.refreshTokenRepository'     => RefreshTokenRepository::class,
            ],
            $eventFactory
        );

        $jwtGuard = new JWTGuard(
            $guardName,
            $jwtHandler,
            $userProvider,
            $request,
            (new TestTokenProvider())->setKey($accessTokenProviderKey),
            $accessTokenTTL,
            (new TestTokenProvider())->setKey($refreshTokenProviderKey),
            $refreshTokenRepository,
            $eventFactory
        );

        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'extendAuthGuard');

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::on(function (\Closure $concrete) use ($app, $jwtGuard, $guardName) {
                    $concreteJwtGuard = $concrete(
                        $app,
                        $guardName,
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
     */
    public function testGetAccessTokenProvider(): void
    {
        $key = $this->getFaker()->uuid;
        $app = $this->createApp();
        $this->addGetConfig(
            $app,
            [
                'jwt.accessTokenProvider.class' => TestTokenProvider::class,
                'jwt.accessTokenProvider.key'   => $key,
            ]
        );

        $registrar = $this->createRegistrar($app);

        $tokenProvider = $this->runReflectionMethod($registrar, 'getAccessTokenProvider');

        $this->assertEquals((new TestTokenProvider())->setKey($key), $tokenProvider);
    }

    /**
     * @return void
     */
    public function testGetRefreshTokenProvider(): void
    {
        $key = $this->getFaker()->uuid;
        $app = $this->createApp();
        $this->addGetConfig(
            $app,
            [
                'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
                'jwt.refreshTokenProvider.key'   => $key,
            ]
        );

        $registrar = $this->createRegistrar($app);

        $tokenProvider = $this->runReflectionMethod($registrar, 'getRefreshTokenProvider');

        $this->assertEquals((new TestTokenProvider())->setKey($key), $tokenProvider);
    }

    /**
     * @return void
     */
    public function testGetRefreshTokenProviderWithoutTokenProvider(): void
    {
        $registrar = $this->createRegistrar($this->createApp());

        $this->assertEmpty($this->runReflectionMethod($registrar, 'getRefreshTokenProvider'));
    }

    /**
     * @return void
     */
    public function testGetRefreshTokenProviderWithoutKey(): void
    {
        $app = $this->createApp();
        $this->addGetConfig(
            $app,
            [
                'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
            ]
        );

        $registrar = $this->createRegistrar($app);

        $this->expectException(InvalidTokenProviderKeyException::class);

        $this->runReflectionMethod($registrar, 'getRefreshTokenProvider');
    }

    /**
     * @return void
     */
    public function testRegister(): void
    {
        $app = $this->createApp();
        $registrar = $this->createRegistrar($app);

        $this->assertEquals($registrar, $registrar->register());

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                JWTFactoryContract::class,
                JWTFactory::class
            )
            ->once();
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
                JWTHandlerContract::class,
                Mockery::any()
            )
            ->once();
        $app
            ->shouldHaveReceived('singleton')
            ->with(
                TokenBlacklist::class,
                Mockery::any()
            )
            ->once();
    }

    /**
     * @return void
     */
    public function testBoot(): void
    {
        $authManager = Mockery::spy(AuthManager::class);
        $app = $this->createApp();
        $this->addGet($app, $authManager);

        $registrar = $this->createRegistrar($app);

        $this->assertEquals($registrar, $registrar->boot());

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::any()
            )
            ->once();
    }

    //endregion

    /**
     * @param Container|null $app
     *
     * @return Registrar|MockInterface
     */
    private function createRegistrar(Container $app = null): Registrar
    {
        return new Registrar($app ?: $this->createApp());
    }

    /**
     * @return Container|MockInterface
     */
    private function createApp(): Container
    {
        return Mockery::spy(Container::class);
    }

    /**
     * @param Container|MockInterface     $app
     * @param AuthManager|null            $authManager
     * @param TokenBlacklist|null         $withTokenBlacklist
     * @param Request|null                $request
     * @param Dispatcher|null             $eventDispatcher
     * @param JWTHandlerContract|null     $jwtHandler
     * @param RefreshTokenRepository|null $refreshTokenRepository
     * @param Builder|null                $builder
     * @param Parser|null                 $parser
     * @param JWTFactoryContract|null     $jwtFactory
     * @param array                       $config
     * @param EventFactory|null           $eventFactory
     *
     * @return RegistrarTest
     */
    private function addGet(
        Container $app,
        AuthManager $authManager = null,
        TokenBlacklist $withTokenBlacklist = null,
        Request $request = null,
        Dispatcher $eventDispatcher = null,
        JWTHandlerContract $jwtHandler = null,
        RefreshTokenRepository $refreshTokenRepository = null,
        Builder $builder = null,
        Parser $parser = null,
        JWTFactoryContract $jwtFactory = null,
        array $config = [],
        EventFactory $eventFactory = null
    ): RegistrarTest {
        $app
            ->shouldReceive('get')
            ->andReturnUsing(
                function (string $argument) use (
                    $authManager,
                    $withTokenBlacklist,
                    $request,
                    $eventDispatcher,
                    $jwtHandler,
                    $refreshTokenRepository,
                    $builder,
                    $parser,
                    $jwtFactory,
                    $config,
                    $eventFactory
                ) {
                    switch ($argument) {
                        case 'auth':
                            return $authManager;

                        case JWTHandlerContract::class:
                            return $jwtHandler ?: Mockery::mock(JWTHandlerContract::class);

                        case 'request':
                            return $request ?: new Request();

                        case Dispatcher::class:
                            return $eventDispatcher;

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

                        case 'config':
                            return $config;

                        case EventFactory::class:
                            return $eventFactory;

                        default:
                            return $this->getFaker()->uuid;
                    }
                }
            );

        return $this;
    }

    /**
     * @param Container|MockInterface $app
     * @param array                     $config
     *
     * @return $this
     */
    private function addGetConfig(Container $app, array $config = [])
    {
        $app
            ->shouldReceive('get')
            ->with('config')
            ->andReturn($config);

        return $this;
    }

    /**
     * @param Container|MockInterface $app
     * @param mixed|null                $concrete
     *
     * @return RegistrarTest
     */
    private function addMake(Container $app, $concrete = null): RegistrarTest
    {
        $app
            ->shouldReceive('make')
            ->andReturn($concrete);

        return $this;
    }
}
