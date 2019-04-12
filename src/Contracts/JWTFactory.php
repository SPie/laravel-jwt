<?php

namespace SPie\LaravelJWT\Contracts;

use Lcobucci\JWT\Token;

/**
 * Interface JWTFactory
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWTFactory
{

    /**
     * @param Token $token
     *
     * @return JWT
     */
    public function createJWT(Token $token): JWT;
}
