<?php

use SPie\LaravelJWT\Providers\Registrar;

return [
    Registrar::SETTING_SECRET                   => env('JWT_SECRET'),
    Registrar::SETTING_ISSUER                   => env('JWT_ISSUER'),
    Registrar::SETTING_SIGNER                   => env(
        'JWT_SIGNER', Lcobucci\JWT\Signer\Hmac\Sha256::class
    ),
    Registrar::SETTING_ACCESS_TOKEN_PROVIDER    => [
        Registrar::SETTING_CLASS => env(
            'JWT_ACCESS_TOKEN_PROVIDER', SPie\LaravelJWT\TokenProvider\HeaderTokenProvider::class
        ),
        Registrar::SETTING_KEY   => env('JWT_ACCESS_TOKEN_KEY', 'Authorization'),
        Registrar::SETTING_TTL   => env('JWT_ACCESS_TOKEN_TTL', 10)
    ],
    Registrar::SETTING_TOKEN_BLACKLIST          => env(
        'JWT_BLACKLIST', SPie\LaravelJWT\Blacklist\CacheTokenBlacklist::class
    ),
    Registrar::SETTING_REFRESH_TOKEN_PROVIDER   => [
        Registrar::SETTING_CLASS => env('JWT_REFRESH_TOKEN_PROVIDER', null),
        Registrar::SETTING_KEY   => env('JWT_REFRESH_TOKEN_KEY', null),
        Registrar::SETTING_TTL   => env('JWT_REFRESH_TOKEN_TTL', null)
    ],
    Registrar::SETTING_REFRESH_TOKEN_REPOSITORY => env('JWT_REFRESH_TOKEN_REPOSITORY', null)
];
