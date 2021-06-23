<?php

namespace SPie\LaravelJWT\Contracts;

use Lcobucci\JWT\Token;

/**
 * Interface Validator
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface Validator
{
    /**
     * @param Token $token
     *
     * @return bool
     */
    public function validate(Token $token): bool;
}
