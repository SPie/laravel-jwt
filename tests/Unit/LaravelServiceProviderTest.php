<?php

use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Providers\LaravelServiceProvider;

/**
 * Class LaravelServiceProviderTest
 */
final class LaravelServiceProviderTest extends TestCase
{

    use TestHelper;

    //region Tests

    /**
     * @return void
     */
    public function testBoot(): void
    {
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

        $laravelServiceProvider->boot();

        $this->assertArrayHasKey(LaravelServiceProvider::class, $laravelServiceProvider::$publishes);
        $keys = \array_keys($laravelServiceProvider::$publishes[LaravelServiceProvider::class]);
        $values = \array_values($laravelServiceProvider::$publishes[LaravelServiceProvider::class]);
        $this->assertEquals(1, \preg_match('/config\/jwt.php/', \array_shift($keys)));
        $this->assertEquals($configPath, \array_shift($values));
        $this->assertArrayHasKey('config', $laravelServiceProvider::$publishGroups);
        $keys = \array_keys($laravelServiceProvider::$publishGroups['config']);
        $values = \array_values($laravelServiceProvider::$publishGroups['config']);
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
    }

    //endregion

    //region Mocks

    /**
     * @param Application|null $app
     *
     * @return LaravelServiceProvider|MockInterface
     */
    private function createLaravelServiceProvider(Application $app = null): LaravelServiceProvider
    {
        return new LaravelServiceProvider($app ?: $this->createApp());
    }

    /**
     * @param Repository|null  $configRepository
     * @param AuthManager|null $authManager
     *
     * @return Application|MockInterface
     */
    private function createApp(Repository $configRepository = null, AuthManager $authManager = null): Application
    {
        $app = Mockery::spy(Application::class, ArrayAccess::class);
        $app
            ->shouldReceive('offsetGet')
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
