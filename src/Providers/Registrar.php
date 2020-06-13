<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\Registrar as RegistrarContract;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\JWTHandler;

/**
 * Class Registrar
 *
 * @package SPie\LaravelJWT\Providers
 */
final class Registrar implements RegistrarContract
{
    const SETTING_JWT                      = 'jwt';
    const SETTING_SECRET                   = 'secret';
    const SETTING_ISSUER                   = 'issuer';
    const SETTING_TTL                      = 'ttl';
    const SETTING_SIGNER                   = 'signer';
    const SETTING_ACCESS_TOKEN_PROVIDER    = 'accessTokenProvider';
    const SETTING_REFRESH_TOKEN_PROVIDER   = 'refreshTokenProvider';
    const SETTING_CLASS                    = 'class';
    const SETTING_KEY                      = 'key';
    const SETTING_TOKEN_BLACKLIST          = 'tokenBlacklist';
    const SETTING_REFRESH_TOKEN_REPOSITORY = 'refreshTokenRepository';
    const SETTING_IP_CHECK_ENABLED         = 'ipCheckEnabled';

    /**
     * @var Container
     */
    private Container $app;

    /**
     * Registrar constructor.
     *
     * @param Container $app
     */
    public function __construct(Container $app)
    {
        $this->app = $app;
    }

    /**
     * @return Container
     */
    private function getApp(): Container
    {
        return $this->app;
    }

    /**
     * @return $this
     */
    public function register(): self
    {
        return $this
            ->registerJWTFactory()
            ->registerJWTHandler()
            ->registerTokenBlacklist();
    }

    /**
     * @return $this
     */
    public function boot(): self
    {
        return $this->extendAuthGuard();
    }

    /**
     * @return $this
     */
    private function registerJWTFactory(): self
    {
        $this->getApp()->singleton(JWTFactoryContract::class, JWTFactory::class);

        return $this;
    }

    /**
     * @return $this
     */
    private function registerJWTHandler(): self
    {
        $this->getApp()->bind(Builder::class);
        $this->getApp()->bind(Parser::class);

        $this->getApp()->singleton(JWTHandlerContract::class, function () {
            $signerClass = $this->getSignerSetting();

            return new JWTHandler(
                $this->getSecretSetting(),
                $this->getIssuerSetting(),
                $this->getApp()->get(JWTFactoryContract::class),
                $this->getApp()->get(Builder::class),
                $this->getApp()->get(Parser::class),
                new $signerClass()
            );
        });

        return $this;
    }

    /**
     * @return $this
     */
    private function registerTokenBlacklist(): self
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
     * @return $this
     */
    private function extendAuthGuard(): self
    {
        $this->getApp()->get('auth')->extend('jwt', function ($app, $name, array $config) {
            $jwtGuard = new JWTGuard(
                $name,
                $this->getApp()->get(JWTHandlerContract::class),
                $this->getApp()->get('auth')->createUserProvider($config['provider']),
                $this->getApp()->get('request'),
                $this->getAccessTokenProvider(),
                $this->getAccessTokenTTLSetting(),
                $this->getRefreshTokenProvider(),
                $this->getApp()->get($this->getRefreshTokenRepositoryClass()),
                $this->getApp()->get(EventFactory::class),
                $this->getApp()->get(TokenBlacklist::class),
                $this->getRefreshTokenTTLSetting(),
                $this->getApp()->get(Dispatcher::class),
                $this->getIpCheckEnabledSetting()
            );

            $this->getApp()->refresh('request', $jwtGuard, 'setRequest');

            return $jwtGuard;
        });

        return $this;
    }

    /**
     * @return TokenProvider
     */
    private function getAccessTokenProvider(): TokenProvider
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
    private function getRefreshTokenProvider(): ?TokenProvider
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
    private function getSecretSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_SECRET);
    }

    /**
     * @return string
     */
    private function getIssuerSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ISSUER);
    }

    /**
     * @return string
     */
    private function getSignerSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_SIGNER);
    }

    /**
     * @return string
     */
    private function getAccessTokenProviderClassSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_CLASS);
    }

    /**
     * @return string
     */
    private function getAccessTokenProviderKeySetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_KEY);
    }

    /**
     * @return int
     */
    private function getAccessTokenTTLSetting(): int
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_TTL);
    }

    /**
     * @return string|null
     */
    private function getBlacklistSetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_TOKEN_BLACKLIST);
    }

    /**
     * @return string|null
     */
    private function getRefreshTokenProviderClassSetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_CLASS);
    }

    /**
     * @return string|null
     */
    private function getRefreshTokenProviderKeySetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_KEY);
    }

    /**
     * @return int|null
     */
    private function getRefreshTokenTTLSetting(): ?int
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_TTL);
    }

    /**
     * @return string|null
     */
    private function getRefreshTokenRepositoryClass(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_REPOSITORY);
    }

    /**
     * @return bool
     */
    private function getIpCheckEnabledSetting(): bool
    {
        return $this->getJWTConfig(self::SETTING_IP_CHECK_ENABLED, false);
    }

    /**
     * @param string     $key
     * @param mixed|null $default
     *
     * @return string|null
     */
    private function getJWTConfig(string $key, $default = null): ?string
    {
        return $this->getApp()->get('config')[self::SETTING_JWT . '.' . $key] ?? $default;
    }
}
