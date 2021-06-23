<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\Validator;
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
    private string $secret;

    /**
     * @var string
     */
    private string $issuer;

    /**
     * @var JWTFactory
     */
    private JWTFactory $jwtFactory;

    /**
     * @var Builder
     */
    private Builder $builder;

    /**
     * @var Parser
     */
    private Parser $parser;

    /**
     * @var Signer
     */
    private Signer $signer;

    /**
     * @var Validator
     */
    private Validator $validator;

    /**
     * JWTHandler constructor.
     *
     * @param string     $secret
     * @param string     $issuer
     * @param JWTFactory $jwtFactory
     * @param Builder    $builder
     * @param Parser     $parser
     * @param Signer     $signer
     * @param Validator  $validator
     *
     * @throws InvalidSecretException
     */
    public function __construct(
        string $secret,
        string $issuer,
        JWTFactory $jwtFactory,
        Builder $builder,
        Parser $parser,
        Signer $signer,
        Validator $validator
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
        $this->validator = $validator;
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

        if (!$this->validator->validate($token)) {
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
        [$issuedAt, $expiresAt] = $this->createTimestamps($ttl);

        $builder = $this->getNewBuilder()
            ->issuedBy($this->getIssuer())
            ->relatedTo($subject)
            ->issuedAt($issuedAt);

        if ($expiresAt) {
            $builder->expiresAt($expiresAt);
        }

        foreach ($payload as $name => $value) {
            $builder->withClaim($name, $value);
        }

        return $this->getJWTFactory()->createJWT(
            $builder->getToken($this->getSigner(), new Key($this->getSecret()))
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
