<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\Registrar as RegistrarContract;
use SPie\LaravelJWT\Providers\LaravelServiceProvider;
use SPie\LaravelJWT\Providers\Registrar;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class LaravelServiceProviderTest
 */
final class LaravelServiceProviderTest extends TestCase
{
    use ReflectionMethodHelper;
    use TestHelper;

    //region Tests

    /**
     * @return void
     */
    public function testConstruct(): void
    {
        $app = $this->createApp();

        $laravelServiceProvider = new LaravelServiceProvider($app);
        $this->assertEquals($app, $this->getPrivateProperty($laravelServiceProvider, 'app'));
        $registrar = $this->getPrivateProperty($laravelServiceProvider, 'registrar');
        $this->assertInstanceOf(Registrar::class, $registrar);
        $this->assertEquals($app, $this->getPrivateProperty($registrar, 'app'));
    }

    /**
     * @return void
     */
    public function testRegister(): void
    {
        $registrar = Mockery::spy(RegistrarContract::class);

        $laravelServiceProvider = $this->createLaravelServiceProvider();
        $this->setPrivateProperty($laravelServiceProvider, 'registrar', $registrar);

        $this->assertEmpty($laravelServiceProvider->register());

        $registrar
            ->shouldHaveReceived('register')
            ->once();
    }

    /**
     * @return void
     */
    public function testBoot(): void
    {
        $registrar = Mockery::spy(RegistrarContract::class);
        $configPath = $this->getFaker()->uuid;
        $configRepository = $this->createConfigRepository();
        $configRepository
            ->shouldReceive('get')
            ->andReturn([]);
        $app = $this->createApp($configRepository);
        $app
            ->shouldReceive('basePath')
            ->andReturn($configPath);
        $laravelServiceProvider = $this->createLaravelServiceProvider($app);
        $this->setPrivateProperty($laravelServiceProvider, 'registrar', $registrar);

        $laravelServiceProvider->boot();

        $publishes = $this->getPrivateProperty($laravelServiceProvider, 'publishes');
        $publishGroups = $this->getPrivateProperty($laravelServiceProvider, 'publishGroups');

        $this->assertArrayHasKey(LaravelServiceProvider::class, $publishes);
        $keys = \array_keys($publishes[LaravelServiceProvider::class]);
        $values = \array_values($publishes[LaravelServiceProvider::class]);
        $this->assertEquals(1, \preg_match('/config\/jwt.php/', \array_shift($keys)));
        $this->assertEquals($configPath, \array_shift($values));
        $this->assertArrayHasKey('config', $publishGroups);
        $keys = \array_keys($publishGroups['config']);
        $values = \array_values($publishGroups['config']);
        $this->assertEquals(1, \preg_match('/config\/jwt.php/', \array_shift($keys)));
        $this->assertEquals($configPath, \array_shift($values));
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
        $registrar
            ->shouldHaveReceived('boot')
            ->once();
    }

    //endregion

    //region Mocks

    /**
     * @param Container|null $app
     *
     * @return LaravelServiceProvider|MockInterface
     */
    private function createLaravelServiceProvider(Container $app = null): LaravelServiceProvider
    {
        return new LaravelServiceProvider($app ?: $this->createApp());
    }

    /**
     * @param Repository|null  $configRepository
     * @param AuthManager|null $authManager
     *
     * @return Container|MockInterface
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

    //endregion
}
