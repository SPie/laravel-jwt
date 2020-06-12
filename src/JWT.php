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
            $this->getToken()->getClaims()
        );
    }

    /**
     * @param string $claim
     * @param bool   $required
     *
     * @return mixed|null
     *
     * @throws MissingClaimException
     */
    public function getClaim(string $claim, bool $required = true)
    {
        try {
            return $this->getToken()->getClaim($claim);
        } catch (\OutOfBoundsException $e) {
            if ($required) {
                throw new MissingClaimException($claim);
            }
        }

        return null;
    }

    /**
     * @return string
     *
     * @throws MissingClaimException
     */
    public function getIssuer(): string
    {
        return $this->getClaim(self::CLAIM_ISSUER);
    }

    /**
     * @return string
     *
     * @throws MissingClaimException
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
        $expiresAt = $this->getClaim(self::CLAIM_EXPIRES_AT, false);

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
