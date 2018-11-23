<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use SPie\LaravelJWT\Exceptions\BeforeValidException;
use SPie\LaravelJWT\Exceptions\TokenExpiredException;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\InvalidSignatureException;

/**
 * Class JWTHandler
 *
 * @package SPie\LaravelJWT
 */
class JWTHandler
{

    const HASH_ALGO_HS256 = 'HS256';

    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $issuer;

    /**
     * @var int|null
     */
    private $ttl;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * JWTHandler constructor.
     *
     * @param string      $secret
     * @param string      $issuer
     * @param int|null    $ttl
     * @param Signer|null $signer
     *
     * @throws InvalidSecretException
     */
    public function __construct(
        string $secret,
        string $issuer,
        int $ttl = null,
        Signer $signer = null
    )
    {
        if (empty($secret)) {
            throw new InvalidSecretException();
        }

        $this->secret = $secret;
        $this->issuer = $issuer;
        $this->ttl = $ttl;
        $this->signer = $signer ?: new Sha256();
    }

    /**
     * @return string
     */
    protected function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @return string
     */
    protected function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * @return int|null
     */
    protected function getTtl(): ?int
    {
        return $this->ttl;
    }

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return $this->signer;
    }

    /**
     * @param string $token
     *
     * @return JWT
     *
     * @throws BeforeValidException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     * @throws InvalidSignatureException
     * @throws \Exception
     */
    public function getValidJWT(string $token): JWT
    {
        try {
            $token = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidTokenException();
        }

        if (!$token->verify($this->getSigner(), $this->getSecret())) {
            throw new InvalidSignatureException();
        }

        if ($token->isExpired()) {
            throw new TokenExpiredException();
        }

        $jwt = new JWT($token);
        if ($jwt->getIssuedAt() > new \DateTimeImmutable()) {
            throw new BeforeValidException();
        }

        return $jwt;
    }

    /**
     * @param string $subject
     * @param array  $payload
     *
     * @return JWT
     *
     * @throws \Exception
     */
    public function createJWT(string $subject, array $payload = []): JWT
    {
        list($issuedAt, $expiresAt) = $this->createTimestamps();

        $builder = (new Builder())
            ->setIssuer($this->getIssuer())
            ->setSubject($subject)
            ->setIssuedAt($issuedAt)
            ->setExpiration($expiresAt);

        foreach ($payload as $name => $value) {
            $builder->set($name, $value);
        }

        return new JWT(
            $builder->sign($this->getSigner(), $this->getSecret())->getToken()
        );
    }

    /**
     * @return array
     *
     * @throws \Exception
     */
    protected function createTimestamps(): array
    {
        $issuedAt = new \DateTimeImmutable();

        return [
            $issuedAt->getTimestamp(),
            $this->getTtl()
                ? (clone $issuedAt)
                    ->add(new \DateInterval('PT' . $this->getTtl() . 'M'))
                    ->getTimestamp()
                : null
        ];
    }
}
