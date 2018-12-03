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

    public function __construct()
    {
        $this->refreshTokens = new Collection();
    }

    /**
     * @return JWT[]|Collection
     */
    public function getRefreshTokens(): Collection
    {
        return $this->refreshTokens;
    }

    /**
     * @param JWT $refreshToken
     *
     * @return RefreshTokenRepository
     */
    public function storeRefreshToken(JWT $refreshToken): RefreshTokenRepository
    {
        $this->refreshTokens->push($refreshToken);

        return $this;
    }
}
