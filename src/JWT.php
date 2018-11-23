<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Token;

/**
 * Class Token
 *
 * @package SPie\LaravelJWT
 */
class JWT
{

    const CLAIM_ISSUER     = 'iss';
    const CLAIM_SUBJECT    = 'sub';
    const CLAIM_AUDIENCE   = 'aud';
    const CLAIM_EXPIRES_AT = 'exp';
    const CLAIM_NOT_BEFORE = 'nbf';
    const CLAIM_ISSUED_AT  = 'iat';
    const CLAIM_JWT_ID     = 'jti';

    /**
     * @var Token
     */
    private $token;

    /**
     * Token constructor.
     *
     * @param Token $token
     */
    public function __construct(Token $token)
    {
        $this->token = $token;
    }

    /**
     * @return Token
     */
    public function getToken(): Token
    {
        return $this->token;
    }

    /**
     * @return string
     */
    public function getJWT(): string
    {
        return $this->getToken();
    }

    /**
     * @return array
     */
    public function getClaims(): array
    {
        return \array_map(
            function (Claim $claim) {
                return $claim->getValue();
            },
            $this->getToken()->getClaims()
        );
    }

    /**
     * @param string $claim
     *
     * @return mixed|null
     */
    public function getClaim(string $claim)
    {
        try {
            return $this->getToken()->getClaim($claim);
        } catch (\OutOfBoundsException $e) {
            return null;
        }
    }

    /**
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->getToken()->getClaim(self::CLAIM_ISSUER);
    }

    /**
     * @return string
     */
    public function getSubject(): string
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
        $expiresAt = $this->getClaim(self::CLAIM_EXPIRES_AT);

        return $expiresAt
            ? (new \DateTimeImmutable())->setTimestamp($expiresAt)
            : null;
    }

    /**
     * @return \DateTimeImmutable
     *
     * @throws \Exception
     */
    public function getIssuedAt(): \DateTimeImmutable
    {
        return (new \DateTimeImmutable())->setTimestamp($this->getClaim(self::CLAIM_ISSUED_AT));
    }
}
