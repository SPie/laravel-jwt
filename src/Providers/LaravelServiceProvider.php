<?php

namespace SPie\LaravelJWT\Providers;

/**
 * Class LaravelServiceProvider
 *
 * @package SPie\LaravelJWT\Providers
 */
class LaravelServiceProvider extends AbstractServiceProvider
{

    /**
     * @return void
     */
    public function boot(): void
    {
        $path = realpath(__DIR__.'/../../config/jwt.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        parent::boot();
    }
}