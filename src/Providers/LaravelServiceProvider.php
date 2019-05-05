<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

/**
 * Class LaravelServiceProvider
 *
 * @package SPie\LaravelJWT\Providers
 */
final class LaravelServiceProvider extends ServiceProvider
{

    use RegistrarHolder;

    /**
     * LaravelServiceProvider constructor.
     *
     * @param Application $app
     */
    public function __construct(Application $app)
    {
        parent::__construct($app);

        $this->registrar = $this->createRegistrar($app);
    }

    /**
     * @return void
     */
    public function register(): void
    {
        $this->getRegistrar()->register();
    }


    /**
     * @return void
     */
    public function boot(): void
    {
        $path = realpath(__DIR__.'/../../config/jwt.php');

        $this->publishes([$path => $this->getConfigPath()], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->getRegistrar()->boot();
    }

    /**
     * @return string
     */
    protected function getConfigPath(): string
    {
        return $this->app->basePath('config/jwt.php');
    }
}
