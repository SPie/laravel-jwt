<?php

namespace SPie\LaravelJWT\Test\Unit\Providers;

use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\Registrar as RegistrarContract;
use SPie\LaravelJWT\Providers\LumenServiceProvider;
use SPie\LaravelJWT\Providers\Registrar;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\TestHelper;

final class LumenServiceProviderTest extends TestCase
{
    use ReflectionMethodHelper;
    use TestHelper;

    /**
     * @return LumenServiceProvider|MockInterface
     */
    private function createLumenServiceProvider(Container $app = null): LumenServiceProvider
    {
        return new LumenServiceProvider($app ?: $this->createApp());
    }

    /**
     * @return Application|MockInterface
     */
    private function createApp(Repository $configRepository = null, AuthManager $authManager = null): Container
    {
        $app = Mockery::spy(Container::class, \ArrayAccess::class);
        $app
            ->shouldReceive('make')
            ->andReturnUsing(function ($argument) use ($configRepository) {
                switch ($argument) {
                    case 'config':
                        return $configRepository ?: $this->createConfigRepository();
                    default:
                        return null;
                }
            });
        $app
            ->shouldReceive('get')
            ->andReturnUsing(function ($argument) use ($authManager) {
                switch ($argument) {
                    case 'auth':
                        return $authManager ?: $this->createAuthManager();
                    default:
                        return null;
                }
            });

        return $app;
    }

    /**
     * @return Repository|MockInterface
     */
    private function createConfigRepository(): Repository
    {
        return Mockery::spy(Repository::class);
    }

    /**
     * @return AuthManager|MockInterface
     */
    private function createAuthManager(): AuthManager
    {
        return Mockery::spy(AuthManager::class);
    }

    public function testConstruct(): void
    {
        $app = $this->createApp();

        $lumenServiceProvider = $this->createLumenServiceProvider($app);

        $this->assertEquals($app, $this->getPrivateProperty($lumenServiceProvider, 'app'));
        $registrar = $this->getPrivateProperty($lumenServiceProvider, 'registrar');
        $this->assertInstanceOf(Registrar::class, $registrar);
        $this->assertEquals($app, $this->getPrivateProperty($registrar, 'app'));
    }

    public function testRegister(): void
    {
        $registrar = Mockery::spy(RegistrarContract::class);

        $lumenServiceProvider = $this->createLumenServiceProvider();
        $this->setPrivateProperty($lumenServiceProvider, 'registrar', $registrar);

        $lumenServiceProvider->register();

        $registrar
            ->shouldHaveReceived('register')
            ->once();
    }


    public function testBoot(): void
    {
        $registrar = Mockery::spy(RegistrarContract::class);
        $configRepository = $this->createConfigRepository();
        $configRepository
            ->shouldReceive('get')
            ->andReturn([]);
        $app = $this->createApp($configRepository);
        $lumenServiceProvider = $this->createLumenServiceProvider($app);
        $this->setPrivateProperty($lumenServiceProvider, 'registrar', $registrar);

        $lumenServiceProvider->boot();

        $configRepository
            ->shouldHaveReceived('set')
            ->with(
                'jwt',
                Mockery::on(function ($argument) {
                    return \is_array($argument);
                })
            )
            ->once();
        $configRepository
            ->shouldHaveReceived('get')
            ->with(
                'jwt',
                []
            )
            ->once();
        $app
            ->shouldHaveReceived('configure')
            ->with('jwt')
            ->once();
        $registrar
            ->shouldHaveReceived('boot')
            ->once();
    }
}
