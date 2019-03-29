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

    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $issuer;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * JWTHandler constructor.
     *
     * @param string      $secret
     * @param string      $issuer
     * @param Signer|null $signer
     *
     * @throws InvalidSecretException
     */
    public function __construct(
        string $secret,
        string $issuer,
        Signer $signer = null
    )
    {
        if (empty($secret)) {
            throw new InvalidSecretException();
        }

        $this->secret = $secret;
        $this->issuer = $issuer;
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
     * @return Signer
     */
    protected function getSigner(): Signer
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
     * @param string   $subject
     * @param array    $payload
     * @param int|null $ttl
     *
     * @return JWT
     *
     * @throws \Exception
     */
    public function createJWT(string $subject, array $payload = [], int $ttl = null): JWT
    {
        list($issuedAt, $expiresAt) = $this->createTimestamps($ttl);

        $builder = (new Builder())
            ->setIssuer($this->getIssuer())
            ->setSubject($subject)
            ->setIssuedAt($issuedAt);

        if ($expiresAt) {
            $builder->setExpiration($expiresAt);
        }

        foreach ($payload as $name => $value) {
            $builder->set($name, $value);
        }

        return new JWT(
            $builder->sign($this->getSigner(), $this->getSecret())->getToken()
        );
    }

    /**
     * @param int|null $ttl
     *
     * @return array
     *
     * @throws \Exception
     */
    protected function createTimestamps(int $ttl = null): array
    {
        $issuedAt = new \DateTimeImmutable();

        return [
            $issuedAt->getTimestamp(),
            $ttl
                ? (clone $issuedAt)
                    ->add(new \DateInterval('PT' . $ttl . 'M'))
                    ->getTimestamp()
                : null
        ];
    }
}
