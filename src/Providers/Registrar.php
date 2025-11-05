<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validator as LcobucciValidatorContract;
use Lcobucci\JWT\Validation\Validator as LcobucciValidator;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Auth\JWTGuardConfig;
use SPie\LaravelJWT\Contracts\EventFactory as EventFactoryContract;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;
use SPie\LaravelJWT\Contracts\JWTGuard as JWTGuardContract;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\Registrar as RegistrarContract;
use SPie\LaravelJWT\Contracts\TokenBlockList;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Contracts\Validator as ValidatorContract;
use SPie\LaravelJWT\Events\EventFactory;
use SPie\LaravelJWT\Exceptions\InvalidTokenProviderKeyException;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\JWTHandler;
use SPie\LaravelJWT\Validator;

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
    const SETTING_TOKEN_BLOCK_LIST         = 'tokenBlockList';
    const SETTING_REFRESH_TOKEN_REPOSITORY = 'refreshTokenRepository';
    const SETTING_IP_CHECK_ENABLED         = 'ipCheckEnabled';

    private Container $app;

    public function __construct(Container $app)
    {
        $this->app = $app;
    }

    private function getApp(): Container
    {
        return $this->app;
    }

    public function register(): self
    {
        return $this
            ->registerJWTGuard()
            ->registerJWTFactory()
            ->registerJWTHandler()
            ->registerTokenBlockList()
            ->registerJWTGuardConfig()
            ->registerEventFactory()
            ->registerValidator()
            ->registerSigner()
            ->registerSecretKey()
            ->registerSignedWithConstraint()
            ->registerConfiguration()
            ->registerValidator();
    }

    public function boot(): self
    {
        return $this->extendAuthGuard();
    }

    private function registerJWTGuard(): self
    {
        $this->app->singleton(JWTGuardContract::class, fn () => $this->app->get('auth')->guard());

        return $this;
    }

    private function registerJWTFactory(): self
    {
        $this->app->singleton(JWTFactoryContract::class, JWTFactory::class);

        return $this;
    }

    private function registerSignedWithConstraint(): self
    {
        $this->app->singleton(SignedWith::class, fn () => new SignedWith(
            $this->app->get(Signer::class),
            $this->app->get(Key::class)
        ));

        return $this;
    }

    private function registerValidator(): self
    {
        $this->app->singleton(LcobucciValidatorContract::class, LcobucciValidator::class);

        $this->app->singleton(ValidatorContract::class, fn () => new Validator(
            $this->app->get(LcobucciValidatorContract::class),
            $this->app->get(SignedWith::class)
        ));

        return $this;
    }

    private function registerSigner(): self
    {
        $this->app->singleton(Signer::class, function () {
            $signerClass = $this->getSignerSetting();

            return new $signerClass();
        });

        return $this;
    }

    private function registerSecretKey(): self
    {
        $this->app->singleton(Key::class, fn () => InMemory::plainText($this->getSecretSetting()));

        return $this;
    }

    private function registerConfiguration(): self
    {
        $this->app->singleton(Configuration::class, fn () => Configuration::forSymmetricSigner(
            $this->app->get(Signer::class),
            $this->app->get(Key::class)
        ));

        return $this;
    }

    private function registerJWTHandler(): self
    {
        $this->getApp()->singleton(JWTHandlerContract::class, function () {
            /** @var Configuration $configuration */
            $configuration = $this->app->get(Configuration::class);

            return new JWTHandler(
                $this->getIssuerSetting(),
                $this->app->get(JWTFactoryContract::class),
                $this->app->get(ValidatorContract::class),
                $configuration->signer(),
                $configuration->signingKey(),
                $configuration->parser(),
                $configuration->builder()
            );
        });

        return $this;
    }

    private function registerTokenBlockList(): self
    {
        $this->app->singleton(TokenBlockList::class, function () {
            $tokenBlockListClass = $this->getBlockListSetting();

            return !empty($tokenBlockListClass)
                ? $this->app->make($tokenBlockListClass)
                : null;
        });

        return $this;
    }

    private function registerEventFactory(): self
    {
        $this->app->singleton(EventFactoryContract::class, EventFactory::class);

        return $this;
    }

    private function extendAuthGuard(): self
    {
        $this->app->get('auth')->extend('jwt', function ($app, $name, array $config) {
            return new JWTGuard(
                $name,
                $this->app->get(JWTHandlerContract::class),
                $this->app->get('auth')->createUserProvider($config['provider']),
                $this->app->get('request'),
                $this->app->get(JWTGuardConfig::class),
                $this->getAccessTokenProvider(),
                $this->getRefreshTokenProvider(),
                $this->app->get($this->getRefreshTokenRepositoryClass()),
                $this->app->get(EventFactory::class),
                $this->app->get(TokenBlockList::class),
                $this->app->get(Dispatcher::class)
            );
        });

        return $this;
    }

    private function registerJWTGuardConfig(): self
    {
        $this->app->singleton(JWTGuardConfig::class, fn () => new JWTGuardConfig(
            $this->getAccessTokenTTLSetting(),
            $this->getRefreshTokenTTLSetting(),
            $this->getIpCheckEnabledSetting()
        ));

        return $this;
    }

    private function getAccessTokenProvider(): TokenProvider
    {
        $accessTokenProviderClass = $this->getAccessTokenProviderClassSetting();

        return $this->app->make($accessTokenProviderClass)
            ->setKey($this->getAccessTokenProviderKeySetting());
    }

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

        return $this->app->make($refreshTokenProviderClass)
            ->setKey($this->getRefreshTokenProviderKeySetting());
    }

    private function getSecretSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_SECRET);
    }

    private function getIssuerSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ISSUER);
    }

    private function getSignerSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_SIGNER);
    }

    private function getAccessTokenProviderClassSetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_CLASS);
    }

    private function getAccessTokenProviderKeySetting(): string
    {
        return $this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_KEY);
    }

    private function getAccessTokenTTLSetting(): int
    {
        return (int)$this->getJWTConfig(self::SETTING_ACCESS_TOKEN_PROVIDER . '.' . self::SETTING_TTL);
    }

    private function getBlockListSetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_TOKEN_BLOCK_LIST);
    }

    private function getRefreshTokenProviderClassSetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_CLASS);
    }

    private function getRefreshTokenProviderKeySetting(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_KEY);
    }

    private function getRefreshTokenTTLSetting(): ?int
    {
        $refreshTokenTtl = $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_PROVIDER . '.' . self::SETTING_TTL);
        if ($refreshTokenTtl === null) {
            return null;
        }

        return (int)$refreshTokenTtl;
    }

    private function getRefreshTokenRepositoryClass(): ?string
    {
        return $this->getJWTConfig(self::SETTING_REFRESH_TOKEN_REPOSITORY);
    }

    private function getIpCheckEnabledSetting(): bool
    {
        $ipCheckEnabled = $this->getJWTConfig(self::SETTING_IP_CHECK_ENABLED);
        if ($ipCheckEnabled === null) {
            return false;
        }

        return (bool)$ipCheckEnabled;
    }

    private function getJWTConfig(string $key): ?string
    {
        return $this->app->get('config')[self::SETTING_JWT . '.' . $key] ?? null;
    }
}
