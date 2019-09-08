<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface JWT
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWT
{
    const CLAIM_ISSUER     = 'iss';
    const CLAIM_SUBJECT    = 'sub';
    const CLAIM_AUDIENCE   = 'aud';
    const CLAIM_EXPIRES_AT = 'exp';
    const CLAIM_NOT_BEFORE = 'nbf';
    const CLAIM_ISSUED_AT  = 'iat';
    const CLAIM_JWT_ID     = 'jti';

    const CUSTOM_CLAIM_REFRESH_TOKEN = 'rti';
    const CUSTOM_CLAIM_IP_ADDRESS    = 'ipa';

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

    /**
     * @return string|null
     */
    public function getIpAddress(): ?string;
}
