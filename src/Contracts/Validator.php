<?php

namespace SPie\LaravelJWT\Contracts;

use Lcobucci\JWT\Token;

interface Validator
{
    public function validate(Token $token): bool;
}
