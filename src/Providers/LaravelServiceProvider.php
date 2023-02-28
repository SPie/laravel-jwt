<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

final class LaravelServiceProvider extends ServiceProvider
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
        $path = realpath(__DIR__.'/../../config/jwt.php');

        $this->publishes([$path => $this->getConfigPath()], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->registrar->boot();
    }

    protected function getConfigPath(): string
    {
        return $this->app->basePath('config/jwt.php');
    }
}
