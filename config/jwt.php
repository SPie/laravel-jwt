<?php

use SPie\LaravelJWT\Providers\AbstractServiceProvider;

return [
    AbstractServiceProvider::SETTING_SECRET                 => env('JWT_SECRET'),
    AbstractServiceProvider::SETTING_ISSUER                 => env('JWT_ISSUER'),
    AbstractServiceProvider::SETTING_SIGNER                 => env(
        'JWT_SIGNER', Lcobucci\JWT\Signer\Hmac\Sha256::class
    ),
    AbstractServiceProvider::SETTING_ACCESS_TOKEN_PROVIDER  => [
        AbstractServiceProvider::SETTING_CLASS => env(
            'JWT_ACCESS_TOKEN_PROVIDER', SPie\LaravelJWT\TokenProvider\HeaderTokenProvider::class
        ),
        AbstractServiceProvider::SETTING_KEY   => env('JWT_ACCESS_TOKEN_KEY', 'Authorization'),
        AbstractServiceProvider::SETTING_TTL   => env('JWT_ACCESS_TOKEN_TTL', 10)
    ],
    AbstractServiceProvider::SETTING_TOKEN_BLACKLIST        => env(
        'JWT_BLACKLIST', SPie\LaravelJWT\Blacklist\CacheTokenBlacklist::class
    ),
    AbstractServiceProvider::SETTING_REFRESH_TOKEN_PROVIDER => [
        AbstractServiceProvider::SETTING_CLASS => env('JWT_REFRESH_TOKEN_PROVIDER', null),
        AbstractServiceProvider::SETTING_KEY   => env('JWT_REFRESH_TOKEN_KEY', null),
        AbstractServiceProvider::SETTING_TTL   => env('JWT_REFRESH_TOKEN_TTL', null)
    ],
    AbstractServiceProvider::SETTING_REFRESH_TOKEN_REPOSITORY => env('JWT_REFRESH_TOKEN_REPOSITORY', null)
];
