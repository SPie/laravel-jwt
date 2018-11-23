<?php

return [
    'secret'        => env('JWT_SECRET'),
    'issuer'        => env('JWT_ISSUER'),
    'ttl'           => env('JWT_TTL', 10),
    'signer'        => env('JWT_SIGNER', Lcobucci\JWT\Signer\Hmac\Sha256::class),
    'tokenProvider' => [
        'class'  => env('JWT_TOKEN_PROVIDER', SPie\LaravelJWT\TokenProvider\HeaderTokenProvider::class),
        'key'    => env('JWT_TOKEN_KEY','Authorization'),
        'prefix' => env('JWT_TOKEN_PREFIX', 'Bearer'),
    ],
];