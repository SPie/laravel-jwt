<?php

namespace SPie\LaravelJWT\Contracts;

use SPie\LaravelJWT\JWT;

/**
 * Interface TokenBlacklist
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface TokenBlacklist
{

    /**
     * @param JWT $jwt
     *
     * @return TokenBlacklist
     */
    public function revoke(JWT $jwt): TokenBlacklist;

    /**
     * @param string $jwt
     *
     * @return bool
     */
    public function isRevoked(string $jwt): bool;
}
