<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Auth\JWTGuardConfig;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;
use SPie\LaravelJWT\Contracts\JWTGuard as JWTGuardContract;
use SPie\LaravelJWT\Contracts\EventFactory as EventFactoryContract;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlockList;
use SPie\LaravelJWT\Contracts\Validator;
use SPie\LaravelJWT\Events\EventFactory;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\JWTHandler;
use SPie\LaravelJWT\Providers\Registrar;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\TestHelper;
use SPie\LaravelJWT\Test\TestSigner;
use SPie\LaravelJWT\Test\TestTokenProvider;

final class RegistrarTest extends TestCase
{
    use TestHelper;
    use JWTHelper;
    use ReflectionMethodHelper;

    /**
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

    private function addGet(
        MockInterface $app,
        AuthManager $authManager = null,
        TokenBlockList $withTokenBlockList = null,
        Request $request = null,
        Dispatcher $eventDispatcher = null,
        JWTHandlerContract $jwtHandler = null,
        RefreshTokenRepository $refreshTokenRepository = null,
        Builder $builder = null,
        Parser $parser = null,
        JWTFactoryContract $jwtFactory = null,
        array $config = [],
        EventFactoryContract $eventFactory = null,
        JWTGuardConfig $jwtGuardConfig = null,
        Signer $signer = null,
        Validator $validator = null,
        Configuration $configuration = null
    ): RegistrarTest {
        $app
            ->shouldReceive('get')
            ->andReturnUsing(
                function (string $argument) use (
                    $authManager,
                    $withTokenBlockList,
                    $request,
                    $eventDispatcher,
                    $jwtHandler,
                    $refreshTokenRepository,
                    $builder,
                    $parser,
                    $jwtFactory,
                    $config,
                    $eventFactory,
                    $jwtGuardConfig,
                    $signer,
                    $validator,
                    $configuration
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

                        case TokenBlockList::class:
                            return $withTokenBlockList;

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

                        case JWTGuardConfig::class:
                            return $jwtGuardConfig;

                        case Signer::class:
                            return $signer;

                        case Validator::class:
                            return $validator;

                        case Configuration::class:
                            return $configuration;

                        default:
                            return $this->getFaker()->uuid;
                    }
                }
            );

        return $this;
    }

    private function addGetConfig(MockInterface $app, array $config = [])
    {
        $app
            ->shouldReceive('get')
            ->with('config')
            ->andReturn($config);

        return $this;
    }

    private function addMake(MockInterface $app, $concrete = null): RegistrarTest
    {
        $app
            ->shouldReceive('make')
            ->andReturn($concrete);

        return $this;
    }

    private function mockAppMake(MockInterface $app, $concrete, string $class): self
    {
        $app
            ->shouldReceive('make')
            ->with($class)
            ->andReturn($concrete);

        return $this;
    }

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

    public function testRegisterJWTHandler(): void
    {
        $issuer = $this->getFaker()->uuid;
        $parser = $this->createParser();
        $jwtFactory = $this->createJWTFactory();
        $validator = $this->createValidator();
        $configuration = $this->createConfiguration();
        $app = $this->createApp();
        $this->addGet(
            $app,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            $parser,
            $jwtFactory,
            [
                'jwt.signer' => TestSigner::class,
                'jwt.secret' => $this->getFaker()->word,
                'jwt.issuer' => $issuer,
            ],
            null,
            null,
            null,
            $validator,
            $configuration
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
                Mockery::on(function (\Closure $concrete) use ($issuer, $parser, $jwtFactory, $validator, $configuration) {
                    $expectedJwtHandler = new JWTHandler(
                        $issuer,
                        $jwtFactory,
                        $validator,
                        $configuration,
                        $parser
                    );

                    $jwtHandler = $concrete();

                    $this->assertEquals($expectedJwtHandler, $jwtHandler);

                    return ($expectedJwtHandler == $jwtHandler);
                }),
            )
            ->once();
    }

    public function testRegisterTokenBlockList(): void
    {
        $tokenBlockListClass = $this->getFaker()->uuid;

        $app = $this->createApp();
        $this
            ->addGetConfig(
                $app,
                [
                    'jwt.tokenBlockList' => $tokenBlockListClass
                ]
            )
            ->addMake($app, $tokenBlockListClass);

        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'registerTokenBlockList');

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                Mockery::on(function (string $abstract) {
                    return ($abstract == TokenBlockList::class);
                }),
                Mockery::on(function (\Closure $concrete) use ($tokenBlockListClass) {
                    $tokenBlockList = $concrete();

                    return ($tokenBlockList == $tokenBlockListClass);
                })
            )
            ->once();

        $this->assertTrue(true);
    }

    public function testRegisterTokenBlockListWithoutBlockListSetting(): void
    {
        $app = $this->createApp();
        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'registerTokenBlockList');

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                TokenBlockList::class,
                Mockery::on(function (\Closure $concrete) {
                    $tokenBlockList = $concrete();

                    return \is_null($tokenBlockList);
                })
            )
            ->once();

        $app->shouldNotHaveReceived('make');

        $this->assertTrue(true);
    }

    public function testExtendAuthGuard(): void
    {
        $guardName = $this->getFaker()->word;
        $userProvider = Mockery::mock(UserProvider::class);
        $request = new Request();
        $eventDispatcher = Mockery::mock(Dispatcher::class);
        $jwtHandler = Mockery::mock(JWTHandlerContract::class);
        $tokenBlockList = Mockery::mock(TokenBlockList::class);
        $refreshTokenRepository = Mockery::mock(RefreshTokenRepository::class);
        $accessTokenProvider = new TestTokenProvider();
        $refreshTokenProvider = new TestTokenProvider();

        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn($userProvider);

        $eventFactory = $this->createEventFactory();
        $accessTokenProviderKey = $this->getFaker()->uuid;
        $refreshTokenProviderKey = $this->getFaker()->uuid;
        $jwtGuardConfig = $this->createJWTGuardConfig();

        $app = $this->createApp();
        $this
            ->addGet(
                $app,
                $authManager,
                $tokenBlockList,
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
                    'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
                    'jwt.refreshTokenProvider.key'   => $refreshTokenProviderKey,
                    'jwt.refreshTokenRepository'     => RefreshTokenRepository::class,
                ],
                $eventFactory,
                $jwtGuardConfig
            )
            ->mockAppMake($app, $accessTokenProvider, TestTokenProvider::class)
            ->mockAppMake($app, $refreshTokenProvider, TestTokenProvider::class);

        $jwtGuard = new JWTGuard(
            $guardName,
            $jwtHandler,
            $userProvider,
            $request,
            $jwtGuardConfig,
            $accessTokenProvider->setKey($accessTokenProviderKey),
            $refreshTokenProvider->setKey($refreshTokenProviderKey),
            $refreshTokenRepository,
            $eventFactory,
            $tokenBlockList,
            $eventDispatcher
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

        $this->assertTrue(true);
    }

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

        $accessTokenProvider = new TestTokenProvider();
        $refreshTokenProvider = new TestTokenProvider();
        $accessTokenProviderKey = $this->getFaker()->uuid;
        $eventFactory = $this->createEventFactory();
        $refreshTokenProviderKey = $this->getFaker()->word;
        $refreshTokenRepository = $this->createRefreshTokenRepository();
        $jwtGuardConfig = $this->createJWTGuardConfig();

        $app = $this->createApp();
        $this
            ->addGet(
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
                    'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
                    'jwt.refreshTokenProvider.key'   => $refreshTokenProviderKey,
                    'jwt.refreshTokenRepository'     => RefreshTokenRepository::class,
                ],
                $eventFactory,
                $jwtGuardConfig
            )
            ->mockAppMake($app, $accessTokenProvider, TestTokenProvider::class)
            ->mockAppMake($app, $refreshTokenProvider, TestTokenProvider::class);

        $jwtGuard = new JWTGuard(
            $guardName,
            $jwtHandler,
            $userProvider,
            $request,
            $jwtGuardConfig,
            $accessTokenProvider->setKey($accessTokenProviderKey),
            $refreshTokenProvider->setKey($refreshTokenProviderKey),
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

        $this->assertTrue(true);
    }

    public function testRegisterJWTGuardConfig(): void
    {
        $accessTokenTtl = $this->getFaker()->numberBetween();
        $refreshTokenTtl = $this->getFaker()->numberBetween();
        $ipCheckEnabled = $this->getFaker()->boolean;
        $app = $this->createApp();
        $this->addGetConfig(
            $app,
            [
                'jwt.accessTokenProvider.ttl'  => $accessTokenTtl,
                'jwt.refreshTokenProvider.ttl' => $refreshTokenTtl,
                'jwt.ipCheckEnabled'           => $ipCheckEnabled,
            ]
        );
        $jwtGuardConfig = new JWTGuardConfig($accessTokenTtl, $refreshTokenTtl, $ipCheckEnabled);
        $registrar = $this->createRegistrar($app);

        $this->runReflectionMethod($registrar, 'registerJWTGuardConfig');

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                JWTGuardConfig::class,
                Mockery::on(function (\Closure $closure) use ($jwtGuardConfig) {
                    $concreteJWTGuardConfig = $closure();

                    return $jwtGuardConfig == $concreteJWTGuardConfig;
                })
            )
            ->once();
    }

    public function testGetAccessTokenProvider(): void
    {
        $key = $this->getFaker()->uuid;
        $app = $this->createApp();
        $this
            ->addGetConfig(
                $app,
                [
                    'jwt.accessTokenProvider.class' => TestTokenProvider::class,
                    'jwt.accessTokenProvider.key'   => $key,
                ]
            )
            ->mockAppMake($app, new TestTokenProvider(), TestTokenProvider::class);

        $registrar = $this->createRegistrar($app);

        $tokenProvider = $this->runReflectionMethod($registrar, 'getAccessTokenProvider');

        $this->assertEquals((new TestTokenProvider())->setKey($key), $tokenProvider);
    }

    public function testGetRefreshTokenProvider(): void
    {
        $key = $this->getFaker()->uuid;
        $app = $this->createApp();
        $this
            ->addGetConfig(
                $app,
                [
                    'jwt.refreshTokenProvider.class' => TestTokenProvider::class,
                    'jwt.refreshTokenProvider.key'   => $key,
                ]
            )
            ->mockAppMake($app, new TestTokenProvider(), TestTokenProvider::class);

        $registrar = $this->createRegistrar($app);

        $tokenProvider = $this->runReflectionMethod($registrar, 'getRefreshTokenProvider');

        $this->assertEquals((new TestTokenProvider())->setKey($key), $tokenProvider);
    }

    public function testGetRefreshTokenProviderWithoutTokenProvider(): void
    {
        $registrar = $this->createRegistrar($this->createApp());

        $this->assertEmpty($this->runReflectionMethod($registrar, 'getRefreshTokenProvider'));
    }

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
                TokenBlockList::class,
                Mockery::any()
            )
            ->once();
        $app
            ->shouldHaveReceived('singleton')
            ->with(
                JWTGuardConfig::class,
                Mockery::any()
            )
            ->once();
        $app
            ->shouldHaveReceived('singleton')
            ->with(
                JWTGuardContract::class,
                Mockery::any()
            )
            ->once();
        $app
            ->shouldHaveReceived('singleton')
            ->with(
                EventFactoryContract::class,
                EventFactory::class
            )
            ->once();
    }

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
}
