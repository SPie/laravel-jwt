<?php

namespace SPie\LaravelJWT\Contracts;

use Lcobucci\JWT\Token;

interface JWTFactory
{
    public function createJWT(Token $token): JWT;
}
