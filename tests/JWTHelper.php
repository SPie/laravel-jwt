<?php

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Mockery\MockInterface;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\JWT;

/**
 * Trait JWTHelper
 */
trait JWTHelper
{

    /**
     * @param array       $payload
     * @param string|null $secret
     * @param int         $ttl
     *
     * @return Token
     *
     * @throws \Exception
     */
    protected function createToken(array $payload = [], string $secret = null, int $ttl = 0): Token
    {
        $signer = $this->getSigner();
        $builder = (new Builder())
            ->setHeader('alg', $signer->getAlgorithmId());

        foreach ($payload as $key => $value) {
            $builder->set($key, $value);
        }

        if ($ttl !== 0) {
            $expiration = ($ttl > 0)
                ? (new \DateTimeImmutable())->add(new \DateInterval('PT' . $ttl . 'M'))
                : (new \DateTimeImmutable())->sub(new \DateInterval('PT' . (-1 * $ttl) . 'M'));

            $builder->setExpiration($expiration->getTimestamp());
        }

        return $builder
            ->sign($this->getSigner(), $secret ?: $this->getFaker()->uuid)
            ->getToken();
    }

    /**
     * @param string|null $refreshTokenId
     * @param array       $payload
     * @param string|null $secret
     * @param int         $ttl
     *
     * @return Token
     *
     * @throws \Exception
     */
    protected function createRefreshToken(
        array $payload = [],
        string $secret = null,
        int $ttl = 0,
        string $refreshTokenId = null
    ): Token
    {
        return $this->createToken(
            \array_merge(
                $payload,
                [
                    JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshTokenId ?: $this->getFaker()->uuid,
                ]
            ),
            $secret,
            $ttl
        );
    }

    /**
     * @return JWT|MockInterface
     */
    protected function createJWTMock(): JWT
    {
        return Mockery::spy(JWT::class);
    }

    /**
     * @return Token|MockInterface
     */
    protected function createTokenMock(): Token
    {
        return Mockery::spy(Token::class);
    }

    /**
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        return new Sha256();
    }

    /**
     * @param Token|\Exception|null $token
     *
     * @return Builder|MockInterface
     */
    protected function createBuilder(Token $token = null): Builder
    {
        $builder = Mockery::spy(Builder::class);

        return $builder
            ->shouldReceive('setIssuer')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('setSubject')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('setIssuedAt')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('setExpiration')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('set')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('sign')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('getToken')
            ->andReturn($token ?: $this->createTokenMock())
            ->getMock();
    }

    /**
     * @param Token|\Exception|null $token
     *
     * @return Parser|MockInterface
     */
    protected function createParser($token = null): Parser
    {
        $parser = Mockery::spy(Parser::class);

        $parseExpectation = $parser->shouldReceive('parse');
        if ($token instanceof \Exception) {
            $parseExpectation->andThrow($token);

            return $parser;
        }

        $parseExpectation->andReturn($token ?: $this->createTokenMock());

        return $parser;
    }

    /**
     * @return Signer
     */
    protected function createSigner(): Signer
    {
        return Mockery::spy(Signer::class);
    }

    /**
     * @return RefreshTokenRepository|MockInterface
     */
    protected function createRefreshTokenRepositoryMock(): RefreshTokenRepository
    {
        return Mockery::spy(RefreshTokenRepository::class);
    }
}
