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
     * @var Collection
     */
    private $disabledRefreshTokens;

    /**
     * TestRefreshTokenRepository constructor.
     */
    public function __construct()
    {
        $this->refreshTokens = new Collection();
        $this->disabledRefreshTokens = new Collection();
    }

    /**
     * @return JWT[]|Collection
     */
    public function getRefreshTokens(): Collection
    {
        return $this->refreshTokens;
    }

    /**
     * @return Collection|JWT[]
     */
    public function getDisabledRefreshTokens(): Collection
    {
        return $this->disabledRefreshTokens;
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

    /**
     * @param string $refreshTokenId
     *
     * @return RefreshTokenRepository
     */
    public function disableRefreshToken(string $refreshTokenId): RefreshTokenRepository
    {
        $this->disabledRefreshTokens->push($refreshTokenId);

        return $this;
    }
}
