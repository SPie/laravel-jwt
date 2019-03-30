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

        $this->publishes([$path => $this->getConfigPath('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        parent::boot();
    }

    /**
     * @param string $configFile
     *
     * @return string
     */
    protected function getConfigPath(string $configFile): string
    {
        return config_path('jwt.php');
    }
}
