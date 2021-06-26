<?php

namespace SPie\LaravelJWT;

use Carbon\CarbonImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\Validator;
use SPie\LaravelJWT\Exceptions\BeforeValidException;
use SPie\LaravelJWT\Exceptions\TokenExpiredException;
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
    private string $issuer;

    /**
     * @var JWTFactory
     */
    private JWTFactory $jwtFactory;

    /**
     * @var Validator
     */
    private Validator $validator;

    /**
     * @var Configuration
     */
    private Configuration $configuration;

    /**
     * @var Parser
     */
    private Parser $parser;

    /**
     * JWTHandler constructor.
     *
     * @param string        $issuer
     * @param JWTFactory    $jwtFactory
     * @param Validator     $validator
     * @param Configuration $configuration
     * @param Parser        $parser
     */
    public function __construct(
        string $issuer,
        JWTFactory $jwtFactory,
        Validator $validator,
        Configuration $configuration,
        Parser $parser
    ) {
        $this->issuer = $issuer;
        $this->jwtFactory = $jwtFactory;
        $this->validator = $validator;
        $this->configuration = $configuration;
        $this->parser = $parser;
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
        return $this->getJWTFactory()->createJWT($this->getValidToken($token));
    }

    /**
     * @param string $token
     *
     * @return Token
     *
     * @throws BeforeValidException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws TokenExpiredException
     */
    private function getValidToken(string $token): Token
    {
        try {
            $token = $this->parser->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidTokenException();
        }

        if (!$this->validator->validate($token)) {
            throw new InvalidSignatureException();
        }

        $now = new CarbonImmutable();
        if ($token->isExpired($now)) {
            throw new TokenExpiredException();
        }

        if (!$token->hasBeenIssuedBefore($now)) {
            throw new BeforeValidException();
        }

        return $token;
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

        $builder = $this->configuration->builder()
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
            $builder->getToken($this->configuration->signer(), $this->configuration->signingKey())
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
            $issuedAt,
            $ttl
                ? $issuedAt->add(new \DateInterval('PT' . $ttl . 'M'))
                : null
        ];
    }
}
