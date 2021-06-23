<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Token;
use SPie\LaravelJWT\Contracts\JWT as JWTContract;
use SPie\LaravelJWT\Exceptions\MissingClaimException;

/**
 * Class Token
 *
 * @package SPie\LaravelJWT
 */
final class JWT implements JWTContract
{

    /**
     * @var Token
     */
    private Token $token;

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
    private function getToken(): Token
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
            $this->getToken()->claims()->all()
        );
    }

    /**
     * @param string $claim
     * @param bool   $required
     *
     * @return mixed|null
     */
    public function getClaim(string $claim, bool $required = true)
    {
        return $this->getToken()->claims()->get($claim);
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
