<?php

use Illuminate\Contracts\Foundation\Application;
use Mockery\Exception\InvalidCountException;
use Mockery\MockInterface;
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
        $abstractServiceProvider = $this->createAbstractServiceProviderSpy();
        $abstractServiceProvider
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $abstractServiceProvider
            ->shouldReceive('registerJWTHandler')
            ->andReturn($abstractServiceProvider);
        $abstractServiceProvider
            ->shouldReceive('registerTokenProvider')
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
            $abstractServiceProvider->shouldHaveReceived('registerTokenProvider');
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
        $abstractServiceProvider = $this->createAbstractServiceProviderSpy();
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

    //endregion

    /**
     * @param Application|null $app
     *
     * @return AbstractServiceProvider
     */
    private function createAbstractServiceProvider(Application $app = null): AbstractServiceProvider
    {
        return new class($app ?: $this->createApp()) extends AbstractServiceProvider {};
    }

    /**
     * @return AbstractServiceProvider|MockInterface
     */
    private function createAbstractServiceProviderSpy(): AbstractServiceProvider
    {
        return Mockery::spy(AbstractServiceProvider::class);
    }

    /**
     * @return Application|MockInterface
     */
    private function createApp(): Application
    {
        return Mockery::mock(Application::class);
    }
}
