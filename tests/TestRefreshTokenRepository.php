<?php

use Illuminate\Support\Collection;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\JWT;

/**
 * Class TestRefreshTokenRepository
 */
class TestRefreshTokenRepository implements RefreshTokenRepository
{

    /**
     * @var JWT[]|Collection
     */
    private $refreshTokens;

    /**
     * @return JWT[]|Collection
     */
    public function getRefreshTokens(): Collection
    {
        return $this->refreshTokens;
    }
}
