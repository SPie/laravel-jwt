<?php

namespace SPie\LaravelJWT\Blacklist;

use Illuminate\Contracts\Cache\Repository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\JWT;

/**
 * Class CacheTokenBlacklist
 *
 * @package SPie\LaravelJWT\Blacklist
 */
class CacheTokenBlacklist implements TokenBlacklist
{

    const EXPIRATION_MINUTES_DEFAULT = 129600;

    /**
     * @var Repository
     */
    private $repository;

    /**
     * CacheTokenBlacklist constructor.
     *
     * @param Repository $repository
     */
    public function __construct(Repository $repository)
    {
        $this->repository = $repository;
    }

    /**
     * @return Repository
     */
    protected function getRepository(): Repository
    {
        return $this->repository;
    }

    /**
     * @param JWT $jwt
     *
     * @return TokenBlacklist
     *
     * @throws \Exception
     */
    public function revoke(JWT $jwt): TokenBlacklist
    {
        $jwtToken = $jwt->getJWT();

        $expirationMinutes = $this->getExpirationMinutes($jwt->getExpiresAt());

        $expirationMinutes
            ? $this->getRepository()->put(
                $this->hashJwt($jwtToken),
                $jwtToken,
                $expirationMinutes
            )
            : $this->getRepository()->forever(
                $this->hashJwt($jwtToken),
                $jwtToken
            );

        return $this;
    }

    /**
     * @param string $jwt
     *
     * @return bool
     */
    public function isRevoked(string $jwt): bool
    {
        return $this->getRepository()->has($this->hashJwt($jwt));
    }

    /**
     * @param string $jwt
     *
     * @return string
     */
    protected function hashJwt(string $jwt): string
    {
        return \md5($jwt);
    }

    /**
     * @param \DateTimeImmutable $expiration
     *
     * @return int
     *
     * @throws \Exception
     */
    protected function getExpirationMinutes(?\DateTimeImmutable $expiration): int
    {
        if (!$expiration) {
            return 0;
        }

        $minutes = $expiration->getTimestamp() - (new \DateTimeImmutable())->getTimestamp();

        return ($minutes > 0)
            ? $minutes
            : 0;
    }
}
