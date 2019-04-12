<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Token;
use SPie\LaravelJWT\Contracts\JWT as JWTContract;
use SPie\LaravelJWT\Contracts\JWTFactory as JWTFactoryContract;

/**
 * Class JWTFactory
 *
 * @package SPie\LaravelJWT
 */
final class JWTFactory implements JWTFactoryContract
{

    /**
     * @param Token $token
     *
     * @return JWTContract
     */
    public function createJWT(Token $token): JWTContract
    {
        return new JWT($token);
    }
}
