<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface JWT
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWT
{

    /**
     * @return string
     */
    public function getJWT(): string;

    /**
     * @return array
     */
    public function getClaims(): array;

    /**
     * @param string $claim
     * @param bool   $required
     *
     * @return mixed
     */
    public function getClaim(string $claim, bool $required = true);

    /**
     * @return string
     */
    public function getIssuer(): string;

    /**
     * @return string
     */
    public function getSubject(): string;

    /**
     * @return \DateTimeImmutable|null
     */
    public function getExpiresAt(): ?\DateTimeImmutable;

    /**
     * @return \DateTimeImmutable
     */
    public function getIssuedAt(): \DateTimeImmutable;

    /**
     * @return string|null
     */
    public function getRefreshTokenId(): ?string;
}
