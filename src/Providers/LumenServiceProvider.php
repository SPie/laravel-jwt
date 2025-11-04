<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

/**
 * @deprecated Lumen is not longer maintaned and won't be supported in future versions of this package
 */
final class LumenServiceProvider extends ServiceProvider
{
    use RegistrarHolder;

    /**
     * @param Container|Application $app
     */
    public function __construct(Container $app)
    {
        parent::__construct($app);

        $this->registrar = $this->createRegistrar($app);
    }

    public function register(): void
    {
        $this->registrar->register();
    }

    public function boot(): void
    {
        $this->app->configure('jwt');

        $path = realpath(__DIR__.'/../../config/jwt.php');
        $this->mergeConfigFrom($path, 'jwt');

        $this->registrar->boot();
    }
}
