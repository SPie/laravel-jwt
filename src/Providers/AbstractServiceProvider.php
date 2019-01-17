<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Foundation\Application;
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
     * @return Application
     */
    protected function getApp(): Application
    {
        return $this->app;
    }

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
        $this->getApp()->singleton(JWTHandler::class, function () {
            $signerClass = $this->getSignerSetting();

            return new JWTHandler(
                $this->getSecretSetting(),
                $this->getIssuerSetting(),
                $this->getTTLSetting(),
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
        $this->getApp()->singleton(TokenProvider::class, function () {
            $tokenProviderClass = $this->getTokenProviderClassSetting();

            return new $tokenProviderClass(
                $this->getTokenProviderKeySetting(),
                $this->getTokenProviderPrefixSetting()
            );
        });

        return $this;
    }

    /**
     * @return AbstractServiceProvider
     */
    protected function registerTokenBlacklist(): AbstractServiceProvider
    {
        $this->getApp()->singleton(TokenBlacklist::class, function () {
            $tokenBlacklistClass = $this->getBlacklistSetting();

            return !empty($tokenBlacklistClass)
                ? $this->getApp()->make($tokenBlacklistClass)
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
        $this->getApp()['auth']->extend('jwt', function ($app, $name, array $config) {
            $jwtGuard = new JWTGuard(
                $this->getApp()->get(JWTHandler::class),
                $this->getApp()->get('auth')->createUserProvider($config['provider']),
                $this->getApp()['request'],
                $this->getApp()->get(TokenProvider::class),
                $this->getApp()->get(TokenBlacklist::class)
            );

            $this->getApp()->refresh('request', $jwtGuard, 'setRequest');

            return $jwtGuard;
        });

        return $this;
    }

    /**
     * @return string
     */
    protected function getSecretSetting(): string
    {
        return $this->getJWTConfig('secret');
    }

    /**
     * @return string
     */
    protected function getIssuerSetting(): string
    {
        return $this->getJWTConfig('issuer');
    }

    /**
     * @return int
     */
    protected function getTTLSetting(): int
    {
        return $this->getJWTConfig('ttl');
    }

    /**
     * @return string
     */
    protected function getSignerSetting(): string
    {
        return $this->getJWTConfig('signer');
    }

    /**
     * @return string
     */
    protected function getTokenProviderClassSetting(): string
    {
        return $this->getJWTConfig('tokenProvider.class');
    }

    /**
     * @return string
     */
    protected function getTokenProviderKeySetting(): string
    {
        return $this->getJWTConfig('tokenProvider.key');
    }

    /**
     * @return string|null
     */
    protected function getTokenProviderPrefixSetting(): ?string
    {
        return $this->getJWTConfig('tokenProvider.prefix');
    }

    /**
     * @return string|null
     */
    protected function getBlacklistSetting(): ?string
    {
        return $this->getJWTConfig('blacklist');
    }

    /**
     * @param string $key
     *
     * @return mixed|null
     */
    protected function getJWTConfig(string $key)
    {
        return $this->getApp()['config']['jwt.' . $key];
    }
}
