<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Support\ServiceProvider;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Console\GenerateSecret;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\JWTHandler;

/**
 * Class AbstractServiceProvider
 *
 * @package SPie\LaravelJWT\Providers
 */
abstract class AbstractServiceProvider extends ServiceProvider
{

    /**
     * @return void
     */
    public function register(): void
    {
        $this
            ->registerJWTHandler()
            ->registerTokenProvider()
            ->registerTokenBlacklist()
            ->registerCommands();
    }

    /**
     * @return void
     */
    public function boot(): void
    {
        $this->extendAuthGuard();
    }

    /**
     * @return AbstractServiceProvider
     */
    protected function registerJWTHandler(): AbstractServiceProvider
    {
        $this->app->singleton(JWTHandler::class, function () {
            $signerClass = $this->getJWTConfig('signer');

            return new JWTHandler(
                $this->getJWTConfig('secret'),
                $this->getJWTConfig('issuer'),
                $this->getJWTConfig('ttl'),
                new $signerClass()
            );
        });

        return $this;
    }

    /**
     * @return AbstractServiceProvider
     */
    protected function registerTokenProvider(): AbstractServiceProvider
    {
        $this->app->singleton(TokenProvider::class, function () {
            $tokenProviderClass = $this->getJWTConfig('tokenProvider.class');

            return new $tokenProviderClass(
                $this->getJWTConfig('tokenProvider.key'),
                $this->getJWTConfig('tokenProvider.prefix')
            );
        });

        return $this;
    }

    /**
     * @return AbstractServiceProvider
     */
    protected function registerTokenBlacklist(): AbstractServiceProvider
    {
        $this->app->singleton(TokenBlacklist::class, function () {
            $tokenBlacklistClass = $this->getJWTConfig('tokenBlacklist');

            return !empty($tokenBlacklistClass)
                ? $this->app->make($tokenBlacklistClass)
                : null;
        });

        return $this;
    }

    /**
     * @return AbstractServiceProvider
     */
    protected function registerCommands(): AbstractServiceProvider
    {
        $this->commands([
            GenerateSecret::class,
        ]);

        return $this;
    }

    /**
     * @return AbstractServiceProvider
     */
    protected function extendAuthGuard(): AbstractServiceProvider
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $jwtGuard = new JWTGuard(
                $this->app->get(JWTHandler::class),
                $this->app->get('auth')->createUserProvider($config['provider']),
                $this->app['request'],
                $this->app->get(TokenProvider::class),
                $this->app->get(TokenBlacklist::class)
            );

            $this->app->refresh('request', $jwtGuard, 'setRequest');

            return $jwtGuard;
        });

        return $this;
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    protected function getJWTConfig(string $key)
    {
        return $this->app['config']['jwt.' . $key];
    }
}
