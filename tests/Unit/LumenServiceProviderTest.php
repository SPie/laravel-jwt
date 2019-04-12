<?php

use Illuminate\Contracts\Foundation\Application;
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
        $app = Mockery::spy(Application::class);

        $lumenServiceProvider = Mockery::spy(LumenServiceProvider::class, [$app]);
        $lumenServiceProvider
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $lumenServiceProvider
            ->shouldReceive('mergeConfigFrom')
            ->andReturnNull();
        $lumenServiceProvider
            ->shouldReceive('extendAuthGuard')
            ->andReturn($lumenServiceProvider);

        $lumenServiceProvider->boot();

        $app
            ->shouldHaveReceived('configure')
            ->with('jwt')
            ->once();

        $lumenServiceProvider
            ->shouldHaveReceived('mergeConfigFrom')
            ->with(
                Mockery::on(function ($argument) {
                    return (\preg_match('/(\/config\/jwt\.php)/', $argument, $matched) == 1);
                }),
                'jwt'
            )
            ->once();

        $lumenServiceProvider
            ->shouldHaveReceived('extendAuthGuard')
            ->once();

        $this->assertTrue(true);
    }

    //endregion
}
