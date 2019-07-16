<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
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
final class JWTHandler implements JWTHandlerContract
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
     * @var JWTFactory
     */
    private $jwtFactory;

    /**
     * @var Builder
     */
    private $builder;

    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * JWTHandler constructor.
     *
     * @param string      $secret
     * @param string      $issuer
     * @param JWTFactory  $jwtFactory
     * @param Builder     $builder
     * @param Parser      $parser
     * @param Signer|null $signer
     *
     * @throws InvalidSecretException
     */
    public function __construct(
        string $secret,
        string $issuer,
        JWTFactory $jwtFactory,
        Builder $builder,
        Parser $parser,
        Signer $signer
    ) {
        if (empty($secret)) {
            throw new InvalidSecretException();
        }

        $this->secret = $secret;
        $this->issuer = $issuer;
        $this->jwtFactory = $jwtFactory;
        $this->builder = $builder;
        $this->parser = $parser;
        $this->signer = $signer;
    }

    /**
     * @return string
     */
    private function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @return string
     */
    private function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * @return JWTFactory
     */
    private function getJWTFactory(): JWTFactory
    {
        return $this->jwtFactory;
    }

    /**
     * @return Parser
     */
    private function getParser(): Parser
    {
        return $this->parser;
    }

    /**
     * @return Signer
     */
    private function getSigner(): Signer
    {
        return $this->signer;
    }

    /**
     * @return Builder
     */
    private function getNewBuilder(): Builder
    {
        return clone $this->builder;
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
            $token = $this->getParser()->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidTokenException();
        }

        if (!$token->verify($this->getSigner(), $this->getSecret())) {
            throw new InvalidSignatureException();
        }

        if ($token->isExpired()) {
            throw new TokenExpiredException();
        }

        $jwt = $this->getJWTFactory()->createJWT($token);
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

        $builder = $this->getNewBuilder()
            ->setIssuer($this->getIssuer())
            ->setSubject($subject)
            ->setIssuedAt($issuedAt);

        if ($expiresAt) {
            $builder->setExpiration($expiresAt);
        }

        foreach ($payload as $name => $value) {
            $builder->set($name, $value);
        }

        return $this->getJWTFactory()->createJWT(
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
    private function createTimestamps(int $ttl = null): array
    {
        $issuedAt = new \DateTimeImmutable();

        return [
            $issuedAt->getTimestamp(),
            $ttl
                ? $issuedAt
                    ->add(new \DateInterval('PT' . $ttl . 'M'))
                    ->getTimestamp()
                : null
        ];
    }
}
