<?php

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Mockery\Exception\InvalidCountException;
use Mockery\MockInterface;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Console\GenerateSecret;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTHandler;
use SPie\LaravelJWT\Providers\AbstractServiceProvider;

/**
 * Class AbstractServiceProviderTest
 */
class AbstractServiceProviderTest extends TestCase
{

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

        $abstractServiceProvider->register();

        try {
            $abstractServiceProvider->shouldHaveReceived('registerJWTHandler');
            $abstractServiceProvider->shouldHaveReceived('registerTokenBlacklist');
            $abstractServiceProvider->shouldHaveReceived('registerCommands');

            $this->assertTrue(true);
        } catch (InvalidCountException $e) {
            $this->assertTrue(false);
        }
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

        $abstractServiceProvider->boot();

        try {
            $abstractServiceProvider->shouldHaveReceived('extendAuthGuard');

            $this->assertTrue(true);
        } catch (InvalidCountException $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @return void
     *
     * @throws ReflectionException
     */
    public function testRegisterJWTHandler(): void
    {
        $app = $this->createApp();
        $signer = Sha256::class;
        $secret = $this->getFaker()->uuid;
        $issuer = $this->getFaker()->uuid;
        $ttl = $this->getFaker()->numberBetween();

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this
            ->addGetSignerSetting($abstractServiceProvider, $signer)
            ->addGetSecretSetting($abstractServiceProvider, $secret)
            ->addGetIssuerSetting($abstractServiceProvider, $issuer)
            ->addGetTTLSetting($abstractServiceProvider, $ttl);

        $this->getReflectionMethod(
            $this->getReflectionObject($abstractServiceProvider),
            'registerJWTHandler'
        )->invoke($abstractServiceProvider);

        $app
            ->shouldHaveReceived('singleton')
            ->with(
                Mockery::on(function (string $abstract) {
                    return ($abstract == JWTHandler::class);
                }),
                Mockery::on(function (\Closure $concrete) use ($signer, $secret, $issuer, $ttl) {
                    $expectedJwtHandler = new JWTHandler(
                        $secret,
                        $issuer,
                        $ttl,
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

        $this->getReflectionMethod(
            $this->getReflectionObject($abstractServiceProvider),
            'registerTokenBlacklist'
        )->invoke($abstractServiceProvider);

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

        $this->getReflectionMethod(
            $this->getReflectionObject($abstractServiceProvider),
            'registerTokenBlacklist'
        )->invoke($abstractServiceProvider);

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

        $this->getReflectionMethod($this->getReflectionObject($abstractServiceProvider), 'registerCommands')
             ->invoke($abstractServiceProvider);

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
        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn(Mockery::mock(UserProvider::class));

        $app = $this->createApp();
        $this->addGet($app, $authManager);

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this
            ->addGetAccessTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetAccessTokenProviderKeySetting($abstractServiceProvider, $this->getFaker()->uuid)
            ->addGetRefreshTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetRefreshTokenProviderKeySetting($abstractServiceProvider, $this->getFaker()->uuid);

        $this->getReflectionMethod($this->getReflectionObject($abstractServiceProvider), 'extendAuthGuard')
            ->invoke($abstractServiceProvider);

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::on(function (\Closure $concrete) use ($app) {
                    $jwtGuard = $concrete(
                        $app,
                        $this->getFaker()->uuid,
                        [
                            'provider' => Mockery::mock(UserProvider::class),
                        ]
                    );

                    return ($jwtGuard instanceof JWTGuard);
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
        $authManager = Mockery::spy(AuthManager::class);
        $authManager
            ->shouldReceive('createUserProvider')
            ->andReturn(Mockery::mock(UserProvider::class));

        $app = $this->createApp();
        $this->addGet($app, $authManager, false);

        $abstractServiceProvider = $this->createAbstractServiceProvider($app);
        $this
            ->addGetAccessTokenProviderClassSetting($abstractServiceProvider, TestTokenProvider::class)
            ->addGetAccessTokenProviderKeySetting($abstractServiceProvider, $this->getFaker()->uuid)
            ->addGetRefreshTokenProviderClassSetting($abstractServiceProvider, null);

        $this->getReflectionMethod($this->getReflectionObject($abstractServiceProvider), 'extendAuthGuard')
             ->invoke($abstractServiceProvider);

        $authManager
            ->shouldHaveReceived('extend')
            ->with(
                'jwt',
                Mockery::on(function (\Closure $concrete) use ($app) {
                    $jwtGuard = $concrete(
                        $app,
                        $this->getFaker()->uuid,
                        [
                            'provider' => Mockery::mock(UserProvider::class),
                        ]
                    );

                    return ($jwtGuard instanceof JWTGuard);
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

        $tokenProvider = $this->getReflectionMethod(
            $this->getReflectionObject($abstractServiceProvider),
            'getAccessTokenProvider'
        )->invoke($abstractServiceProvider);

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

        $tokenProvider = $this->getReflectionMethod(
            $this->getReflectionObject($abstractServiceProvider),
            'getRefreshTokenProvider'
        )->invoke($abstractServiceProvider);

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
            $this->getReflectionMethod(
                $this->getReflectionObject($abstractServiceProvider),
                'getRefreshTokenProvider'
            )->invoke($abstractServiceProvider)
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

        try {
            $this->getReflectionMethod(
                $this->getReflectionObject($abstractServiceProvider),
                'getRefreshTokenProvider'
            )->invoke($abstractServiceProvider);

            $this->assertTrue(false);
        } catch (InvalidTokenProviderKeyException $e) {
            $this->assertTrue(true);
        }
    }

    //endregion

    /**
     * @param AbstractServiceProvider $abstractServiceProvider
     *
     * @return ReflectionObject
     */
    private function getReflectionObject(AbstractServiceProvider $abstractServiceProvider): \ReflectionObject
    {
        return new \ReflectionObject($abstractServiceProvider);
    }

    /**
     * @param ReflectionObject $reflectionObject
     * @param string           $methodName
     *
     * @return ReflectionMethod
     *
     * @throws ReflectionException
     */
    private function getReflectionMethod(\ReflectionObject $reflectionObject, string $methodName): \ReflectionMethod
    {
        $reflectionMethod = $reflectionObject->getMethod($methodName);
        $reflectionMethod->setAccessible(true);

        return $reflectionMethod;
    }

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
     * @param Application|MockInterface $app
     * @param AuthManager               $authManager
     * @param bool                      $withTokenBlacklist
     *
     * @return AbstractServiceProviderTest
     */
    private function addGet(
        Application $app,
        AuthManager $authManager,
        bool $withTokenBlacklist = true
    ): AbstractServiceProviderTest
    {
        $app
            ->shouldReceive('get')
            ->andReturnUsing(function (string $argument) use ($authManager, $withTokenBlacklist) {
                switch ($argument) {
                    case 'auth':
                        return $authManager;

                    case JWTHandler::class:
                        return Mockery::mock(JWTHandler::class);

                    case 'request':
                        return new Request();

                    case TokenBlacklist::class:
                        return $withTokenBlacklist
                            ? Mockery::mock(TokenBlacklist::class)
                            : null;

                    default:
                        return $this->getFaker()->uuid;
                }
            });

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
    private function addGetTTLSetting(
        AbstractServiceProvider $abstractServiceProvider,
        int $ttl = null
    ): AbstractServiceProviderTest
    {
        $abstractServiceProvider
            ->shouldReceive('getTTLSetting')
            ->andReturn($ttl);

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
