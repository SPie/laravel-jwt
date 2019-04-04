<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Console\GenerateSecret;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTHandler;

/**
 * Class AbstractServiceProvider
 *
 * @package SPie\LaravelJWT\Providers
 */
abstract class AbstractServiceProvider extends ServiceProvider
{

    const SETTING_JWT                    = 'jwt';
    const SETTING_SECRET                 = 'secret';
    const SETTING_ISSUER                 = 'issuer';
    const SETTING_TTL                    = 'ttl';
    const SETTING_SIGNER                 = 'signer';
    const SETTING_ACCESS_TOKEN_PROVIDER  = 'accessTokenProvider';
    const SETTING_REFRESH_TOKEN_PROVIDER = 'refreshTokenProvider';
    const SETTING_CLASS                  = 'class';
    const SETTING_KEY                    = 'key';
    const SETTING_TOKEN_BLACKLIST        = 'tokenBlacklist';
    const SETTING_REFRESH_TOKEN_REPOSITORY = 'refreshTokenRepository';

    /**
     * @return void
     */
    public function register(): void
    {
        $this
            ->registerJWTHandler()
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
            $signerClass = $this->getSignerSetting();

            return new JWTHandler(
                $this->getSecretSetting(),
                $this->getIssuerSetting(),
                $this->app->get(Builder::class),
                $this->app->get(Parser::class),
                new $signerClass()
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
            $tokenBlacklistClass = $this->getBlacklistSetting();

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
        $this->app->get('auth')->extend('jwt', function ($app, $name, array $config) {
            $jwtGuard = new JWTGuard(
                $this->app->get(JWTHandler::class),
                $this->app->get('auth')->createUserProvider($config['provider']),
                $this->app->get('request'),
                $this->getAccessTokenProvider(),
                $this->getAccessTokenTTLSetting(),
                $this->app->get(TokenBlacklist::class),
                $this->getRefreshTokenProvider(),
                $this->getRefreshTokenTTLSetting(),
                $this->getRefreshTokenRepositoryClass()
                    ? $this->app->get($this->getRefreshTokenRepositoryClass())
                    : null
            );

            $this->app->refresh('request', $jwtGuard, 'setRequest');

            return $jwtGuard;
        });

        return $this;
    }

    /**
     * @return TokenProvider
     */
    protected function getAccessTokenProvider(): TokenProvider
    {
        $accessTokenProviderClass = $this->getAccessTokenProviderClassSetting();

        return (new $accessTokenProviderClass())
            ->setKey($this->getAccessTokenProviderKeySetting());
    }

    /**
     * @return TokenProvider|null
     *
     * @throws InvalidTokenProviderKeyException
     */
    protected function getRefreshTokenProvider(): ?TokenProvider
    {
        $refreshTokenProviderClass = $this->getRefreshTokenProviderClassSetting();
        if (empty($refreshTokenProviderClass)) {
            return null;
        }

        $refreshTokenProviderKey = $this->getRefreshTokenProviderKeySetting();
        if (empty($refreshTokenProviderKey)) {
            throw new InvalidTokenProviderKeyException();
        }

        return (new $refreshTokenProviderClass())
            ->setKey($this->getRefreshTokenProviderKeySetting());
    }

    /**
     * @return string
     */
    protected function getSecretSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_SECRET);
    }

    /**
     * @return string
     */
    protected function getIssuerSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ISSUER);
    }

    /**
     * @return string
     */
    protected function getSignerSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_SIGNER);
    }

    /**
     * @return string
     */
    protected function getAccessTokenProviderClassSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_CLASS);
    }

    /**
     * @return string
     */
    protected function getAccessTokenProviderKeySetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_KEY);
    }

    /**
     * @return int
     */
    protected function getAccessTokenTTLSetting(): int
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_TTL);
    }

    /**
     * @return string|null
     */
    protected function getBlacklistSetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_TOKEN_BLACKLIST);
    }

    /**
     * @return string|null
     */
    protected function getRefreshTokenProviderClassSetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_CLASS);
    }

    /**
     * @return string|null
     */
    protected function getRefreshTokenProviderKeySetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_KEY);
    }

    /**
     * @return int|null
     */
    protected function getRefreshTokenTTLSetting(): ?int
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_TTL);
    }

    /**
     * @return string|null
     */
    protected function getRefreshTokenRepositoryClass(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_REPOSITORY);
    }

    /**
     * @param string $key
     *
     * @return string|null
     */
    protected function getJWTConfig(string $key): ?string
    {
        return $this->app['config'][self::SETTING_JWT . '.' . $key];
    }
}
