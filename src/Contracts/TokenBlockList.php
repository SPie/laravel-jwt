<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface TokenBlockList
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface TokenBlockList
{

    /**
     * @param JWT $jwt
     *
     * @return TokenBlockList
     */
    public function revoke(JWT $jwt): self;

    /**
     * @param string $jwt
     *
     * @return bool
     */
    public function isRevoked(string $jwt): bool;
}
