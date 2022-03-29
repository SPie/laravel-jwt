<?php

namespace SPie\LaravelJWT;

use Carbon\CarbonImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\JWTHandler as JWTHandlerContract;
use SPie\LaravelJWT\Contracts\Validator;
use SPie\LaravelJWT\Exceptions\BeforeValidException;
use SPie\LaravelJWT\Exceptions\TokenExpiredException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\InvalidSignatureException;

final class JWTHandler implements JWTHandlerContract
{
    private string $issuer;

    private JWTFactory $jwtFactory;

    private Validator $validator;

    private Signer $signer;

    private Key $signingKey;

    private Parser $parser;

    private Builder $builder;

    public function __construct(
        string $issuer,
        JWTFactory $jwtFactory,
        Validator $validator,
        Signer $signer,
        Key $signingKey,
        Parser $parser,
        Builder $builder
    ) {
        $this->issuer = $issuer;
        $this->jwtFactory = $jwtFactory;
        $this->validator = $validator;
        $this->signer = $signer;
        $this->signingKey = $signingKey;
        $this->parser = $parser;
        $this->builder = $builder;
    }

    /**
     * @throws BeforeValidException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     * @throws InvalidSignatureException
     * @throws \Exception
     */
    public function getValidJWT(string $token): JWT
    {
        return $this->jwtFactory->createJWT($this->getValidToken($token));
    }

    /**
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

    public function createJWT(string $subject, array $payload = [], int $ttl = null): JWT
    {
        [$issuedAt, $expiresAt] = $this->createTimestamps($ttl);

        $builder = $this->builder
            ->issuedBy($this->issuer)
            ->relatedTo($subject)
            ->issuedAt($issuedAt);

        if ($expiresAt) {
            $builder->expiresAt($expiresAt);
        }

        foreach ($payload as $name => $value) {
            $builder->withClaim($name, $value);
        }

        return $this->jwtFactory->createJWT($builder->getToken($this->signer, $this->signingKey));
    }

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
