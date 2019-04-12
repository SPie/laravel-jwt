<?php

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Mockery\MockInterface;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\Contracts\JWT as JWTContract;
use SPie\LaravelJWT\JWTHandler;

/**
 * Trait JWTHelper
 */
trait JWTHelper
{

    /**
     * @param string|null     $secret
     * @param string|null     $issuer
     * @param JWTFactory|null $jwtFactory
     * @param Builder|null    $builder
     * @param Parser|null     $parser
     * @param Signer|null     $signer
     *
     * @return JWTHandler|MockInterface
     */
    protected function createJWTHandler(
        string $secret = null,
        string $issuer = null,
        JWTFactory $jwtFactory = null,
        Builder $builder = null,
        Parser $parser = null,
        Signer $signer = null
    ): JWTHandler
    {
        $jwtHandler = Mockery::spy(
            JWTHandler::class, [
                $secret ?: $this->getFaker()->uuid,
                $issuer ?: $this->getFaker()->uuid,
                $jwtFactory ?: $this->createJWTFactory(),
                $builder ?: $this->createBuilder(),
                $parser ?: $this->createParser(),
                $signer ?: $this->getSigner()
            ]
        );

        return $jwtHandler
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
    }

    /**
     * @return JWT|MockInterface
     */
    protected function createJWT(): JWT
    {
        return Mockery::spy(JWT::class);
    }

    /**
     * @return Token|MockInterface
     */
    protected function createToken(): Token
    {
        return Mockery::spy(Token::class);
    }

    /**
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        return Mockery::spy(Signer::class);
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
            ->andReturn($token ?: $this->createToken())
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

        $parseExpectation->andReturn($token ?: $this->createToken());

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
    protected function createRefreshTokenRepository(): RefreshTokenRepository
    {
        return Mockery::spy(RefreshTokenRepository::class);
    }

    /**
     * @param JWTContract|null $jwt
     *
     * @return JWTFactory
     */
    protected function createJWTFactory(JWTContract $jwt = null): JWTFactory
    {
        return Mockery::spy(JWTFactory::class)
            ->shouldReceive('createJWT')
            ->andReturn($jwt ?: $this->createJWT())
            ->getMock();
    }
}
