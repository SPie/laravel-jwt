<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

/**
 * Class LumenServiceProvider
 *
 * @package SPie\LaravelJWT\Providers
 */
final class LumenServiceProvider extends ServiceProvider
{

    use RegistrarHolder;

    /**
     * LumenServiceProvider constructor.
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
        $this->app->configure('jwt');

        $path = realpath(__DIR__.'/../../config/jwt.php');
        $this->mergeConfigFrom($path, 'jwt');

        $this->getRegistrar()->boot();
    }
}
