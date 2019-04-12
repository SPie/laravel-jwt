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

        $this->publishes([$path => $this->getConfigPath()], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        parent::boot();
    }

    /**
     * @return string
     */
    protected function getConfigPath(): string
    {
        return $this->app->basePath('config/jwt.php');
    }
}
