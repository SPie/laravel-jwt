<?php

namespace SPie\LaravelJWT\Auth;

/**
 * Class JWTGuardConfig
 *
 * @package SPie\LaravelJWT\Auth
 */
final class JWTGuardConfig
{
    /**
     * @var int
     */
    private int $accessTokenTtl;

    /**
     * @var int
     */
    private int $refreshTokenTtl;

    /**
     * @var bool
     */
    private bool $ipCheckEnabled;

    /**
     * JWTGuardConfig constructor.
     *
     * @param int  $accessTokenTtl
     * @param int  $refreshTokenTtl
     * @param bool $ipCheckEnabled
     */
    public function __construct(int $accessTokenTtl, int $refreshTokenTtl, bool $ipCheckEnabled)
    {
        $this->accessTokenTtl = $accessTokenTtl;
        $this->refreshTokenTtl = $refreshTokenTtl;
        $this->ipCheckEnabled = $ipCheckEnabled;
    }

    /**
     * @return int
     */
    public function getAccessTokenTtl(): int
    {
        return $this->accessTokenTtl;
    }

    /**
     * @return int
     */
    public function getRefreshTokenTtl(): int
    {
        return $this->refreshTokenTtl;
    }

    /**
     * @return bool
     */
    public function isIpCheckEnabled(): bool
    {
        return $this->ipCheckEnabled;
    }
}
