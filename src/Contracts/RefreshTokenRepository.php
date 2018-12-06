<?php

namespace SPie\LaravelJWT\Contracts;

use SPie\LaravelJWT\JWT;

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
    public function storeRefreshToken(JWT $refreshToken): RefreshTokenRepository;

    /**
     * @param string $refreshTokenId
     *
     * @return RefreshTokenRepository
     */
    public function revokeRefreshToken(string $refreshTokenId): RefreshTokenRepository;

    /**
     * @param string $refreshTokenId
     *
     * @return bool
     */
    public function isRefreshTokenRevoked(string $refreshTokenId): bool;
}
