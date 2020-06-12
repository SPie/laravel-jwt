<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface RefreshTokenRepository
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface RefreshTokenRepository
{

    /**
     * @param JWT $refreshToken
     *
     * @return RefreshTokenRepository
     */
    public function storeRefreshToken(JWT $refreshToken): self;

    /**
     * @param string $refreshTokenId
     *
     * @return RefreshTokenRepository
     */
    public function revokeRefreshToken(string $refreshTokenId): self;

    /**
     * @param string $refreshTokenId
     *
     * @return bool
     */
    public function isRefreshTokenRevoked(string $refreshTokenId): bool;
}
