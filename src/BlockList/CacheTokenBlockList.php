<?php

namespace SPie\LaravelJWT\BlockList;

use Illuminate\Contracts\Cache\Repository;
use SPie\LaravelJWT\Contracts\TokenBlockList;
use SPie\LaravelJWT\Contracts\JWT;

final class CacheTokenBlockList implements TokenBlockList
{
    const EXPIRATION_MINUTES_DEFAULT = 129600;

    private Repository $repository;

    public function __construct(Repository $repository)
    {
        $this->repository = $repository;
    }

    public function revoke(JWT $jwt): TokenBlockList
    {
        $jwtToken = $jwt->getJWT();

        $expirationMinutes = $this->getExpirationMinutes($jwt->getExpiresAt());

        $expirationMinutes
            ? $this->repository->put(
                $this->hashJwt($jwtToken),
                $jwtToken,
                $expirationMinutes
            )
            : $this->repository->forever(
                $this->hashJwt($jwtToken),
                $jwtToken
            );

        return $this;
    }

    public function isRevoked(string $jwt): bool
    {
        return $this->repository->has($this->hashJwt($jwt));
    }

    private function hashJwt(string $jwt): string
    {
        return \md5($jwt);
    }

    private function getExpirationMinutes(?\DateTimeImmutable $expiration): int
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
