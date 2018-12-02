<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface RefreshToken
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface RefreshToken
{

    public function getCode(): string;

    /**
     * @return string
     */
    public function getToken(): string;

    /**
     * @return \DateTimeImmutable|null
     */
    public function getDisabledAt(): ?\DateTimeImmutable;
}
