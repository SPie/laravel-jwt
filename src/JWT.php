<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use SPie\LaravelJWT\Contracts\JWT as JWTContract;

final class JWT implements JWTContract
{
    private UnencryptedToken $token;

    public function __construct(UnencryptedToken $token)
    {
        $this->token = $token;
    }

    public function getJWT(): string
    {
        return $this->token->toString();
    }

    public function getClaims(): array
    {
        return $this->token->claims()->all();
    }

    /**
     * @return mixed|null
     */
    public function getClaim(string $claim, bool $required = true)
    {
        return $this->token->claims()->get($claim);
    }

    public function getIssuer(): ?string
    {
        return $this->getClaim(self::CLAIM_ISSUER);
    }

    public function getSubject(): ?string
    {
        return $this->getClaim(self::CLAIM_SUBJECT);
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->getClaim(self::CLAIM_EXPIRES_AT, false) ?: null;
    }

    public function getIssuedAt(): ?\DateTimeImmutable
    {
        return $this->getClaim(self::CLAIM_ISSUED_AT) ?: null;
    }

    public function getRefreshTokenId(): ?string
    {
        return $this->getClaim(self::CUSTOM_CLAIM_REFRESH_TOKEN, false);
    }

    public function getIpAddress(): ?string
    {
        return $this->getClaim(self::CUSTOM_CLAIM_IP_ADDRESS, false);
    }
}
