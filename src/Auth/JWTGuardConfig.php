<?php

namespace SPie\LaravelJWT\Auth;

final class JWTGuardConfig
{
    private int $accessTokenTtl;

    private ?int $refreshTokenTtl;

    private bool $ipCheckEnabled;

    public function __construct(int $accessTokenTtl, ?int $refreshTokenTtl, bool $ipCheckEnabled)
    {
        $this->accessTokenTtl = $accessTokenTtl;
        $this->refreshTokenTtl = $refreshTokenTtl;
        $this->ipCheckEnabled = $ipCheckEnabled;
    }

    public function getAccessTokenTtl(): int
    {
        return $this->accessTokenTtl;
    }

    public function getRefreshTokenTtl(): ?int
    {
        return $this->refreshTokenTtl;
    }

    public function isIpCheckEnabled(): bool
    {
        return $this->ipCheckEnabled;
    }
}
