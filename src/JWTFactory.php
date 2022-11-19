<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Token;
use SPie\LaravelJWT\Contracts\JWT as JWTContract;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;

final class JWTFactory implements JWTFactoryContract
{
    public function createJWT(Token $token): JWTContract
    {
        return new JWT($token);
    }
}
