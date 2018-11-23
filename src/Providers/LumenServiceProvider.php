<?php

namespace SPie\LaravelJWT\Providers;

/**
 * Class LumenServiceProvider
 *
 * @package SPie\LaravelJWT\Providers
 */
class LumenServiceProvider extends AbstractServiceProvider
{

    /**
     * @return void
     */
    public function boot(): void
    {
        $this->app->configure('jwt');

        $path = realpath(__DIR__.'/../../config/jwt.php');
        $this->mergeConfigFrom($path, 'jwt');

        parent::boot();
    }
}