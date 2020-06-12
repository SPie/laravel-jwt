<?php

namespace SPie\LaravelJWT\Contracts;

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
    public function revoke(JWT $jwt): self;

    /**
     * @param string $jwt
     *
     * @return bool
     */
    public function isRevoked(string $jwt): bool;
}
