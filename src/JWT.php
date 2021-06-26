<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use SPie\LaravelJWT\Contracts\JWT as JWTContract;

/**
 * Class Token
 *
 * @package SPie\LaravelJWT
 */
final class JWT implements JWTContract
{

    /**
     * @var UnencryptedToken
     */
    private UnencryptedToken $token;

    /**
     * Token constructor.
     *
     * @param UnencryptedToken $token
     */
    public function __construct(UnencryptedToken $token)
    {
        $this->token = $token;
    }

    /**
     * @return string
     */
    public function getJWT(): string
    {
        return $this->token->toString();
    }

    /**
     * @return array
     */
    public function getClaims(): array
    {
        return $this->token->claims()->all();
    }

    /**
     * @param string $claim
     * @param bool   $required
     *
     * @return mixed|null
     */
    public function getClaim(string $claim, bool $required = true)
    {
        return $this->token->claims()->get($claim);
    }

    /**
     * @return string|null
     */
    public function getIssuer(): ?string
    {
        return $this->getClaim(self::CLAIM_ISSUER);
    }

    /**
     * @return string|null
     */
    public function getSubject(): ?string
    {
        return $this->getClaim(self::CLAIM_SUBJECT);
    }

    /**
     * @return \DateTimeImmutable
     *
     * @throws \Exception
     */
    public function getExpiresAt(): ?\DateTimeImmutable
    {
        $expiresAt = $this->getClaim(self::CLAIM_EXPIRES_AT, false);

        return $expiresAt
            ? (new \DateTimeImmutable())->setTimestamp($expiresAt)
            : null;
    }

    /**
     * @return \DateTimeImmutable|null
     */
    public function getIssuedAt(): ?\DateTimeImmutable
    {
        $issuedAt = $this->getClaim(self::CLAIM_ISSUED_AT);
        if (empty($issuedAt)) {
            return null;
        }

        return (new \DateTimeImmutable())->setTimestamp($issuedAt);
    }

    /**
     * @return null|string
     */
    public function getRefreshTokenId(): ?string
    {
        return $this->getClaim(self::CUSTOM_CLAIM_REFRESH_TOKEN, false);
    }

    /**
     * @return string|null
     */
    public function getIpAddress(): ?string
    {
        return $this->getClaim(self::CUSTOM_CLAIM_IP_ADDRESS, false);
    }
}
