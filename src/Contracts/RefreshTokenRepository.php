<?php

namespace SPie\LaravelJWT\Contracts;

interface RefreshTokenRepository
{
    public function storeRefreshToken(JWT $refreshToken): self;

    public function revokeRefreshToken(string $refreshTokenId): self;

    public function isRefreshTokenRevoked(string $refreshTokenId): bool;
}
