<?php

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

        $laravelServiceProvider = Mockery::spy(LaravelServiceProvider::class);
        $laravelServiceProvider
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $laravelServiceProvider
            ->shouldReceive('mergeConfigFrom')
            ->andReturnNull();
        $laravelServiceProvider
            ->shouldReceive('getConfigPath')
            ->andReturn($configPath);
        $laravelServiceProvider
            ->shouldReceive('extendAuthGuard')
            ->andReturn($laravelServiceProvider);

        $laravelServiceProvider->boot();

        $laravelServiceProvider
            ->shouldHaveReceived('publishes')
            ->with(
                Mockery::on(function ($argument) use ($configPath) {
                    $keys = \array_keys($argument);

                    return (
                        \preg_match('/(\/config\/jwt\.php)/', \array_shift($keys)) == 1
                        && \array_shift($argument) == $configPath
                    );
                }),
                'config'
            )
            ->once();

        $laravelServiceProvider
            ->shouldHaveReceived('mergeConfigFrom')
            ->with(
                Mockery::on(function ($argument) {
                    return (\preg_match('/(\/config\/jwt\.php)/', $argument) == 1);
                }),
                'jwt'
            )
            ->once();

        $this->assertTrue(true);
    }

    //endregion
}
