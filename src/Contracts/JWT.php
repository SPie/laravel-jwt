<?php

namespace SPie\LaravelJWT\Contracts;

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

    public function getJWT(): string;

    public function getClaims(): array;

    /**
     * @return mixed|null
     */
    public function getClaim(string $claim, bool $required = true);

    public function getIssuer(): ?string;

    public function getSubject(): ?string;

    public function getExpiresAt(): ?\DateTimeImmutable;

    public function getIssuedAt(): ?\DateTimeImmutable;

    public function getRefreshTokenId(): ?string;

    public function getIpAddress(): ?string;
}
