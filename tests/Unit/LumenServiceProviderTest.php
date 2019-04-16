<?php

use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Providers\LumenServiceProvider;

/**
 * Class LumenServiceProviderTest
 */
final class LumenServiceProviderTest extends TestCase
{

    use TestHelper;

    //region Tests

    /**
     * @return void
     */
    public function testBoot(): void
    {
        $configRepository = $this->createConfigRepository();
        $configRepository
            ->shouldReceive('get')
            ->andReturn([]);
        $app = $this->createApp($configRepository);
        $lumenServiceProvider = $this->createLumenServiceProvider($app);

        $this->assertEmpty($lumenServiceProvider->boot());

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
    }

    //endregion

    //region Mocks

    /**
     * @param Application|null $app
     *
     * @return LumenServiceProvider|MockInterface
     */
    private function createLumenServiceProvider(Application $app = null): LumenServiceProvider
    {
        return new LumenServiceProvider($app ?: $this->createApp());
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
