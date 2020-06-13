<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Mockery;
use Mockery\MockInterface;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTHandler;

/**
 * Trait JWTHelper
 */
trait JWTHelper
{

    /**
     * @return JWTGuard
     */
    protected function createJWTGuard(): JWTGuard
    {
        return Mockery::spy(JWTGuard::class);
    }

    /**
     * @return JWTHandler|MockInterface
     */
    protected function createJWTHandler(): JWTHandler
    {
        return Mockery::spy(JWTHandler::class);
    }

    /**
     * @return JWT|MockInterface
     */
    protected function createJWT(): JWT
    {
        return Mockery::spy(JWT::class);
    }

    /**
     * @param MockInterface $jwt
     * @param string|null   $ipAddress
     *
     * @return $this
     */
    private function mockJWTGetIpAddress(MockInterface $jwt, ?string $ipAddress)
    {
        $jwt
            ->shouldReceive('getIpAddress')
            ->andReturn($ipAddress);

        return $this;
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
     * @param RefreshTokenRepository|MockInterface $refreshTokenRepository
     * @param JWT                                  $refreshToken
     *
     * @return $this
     */
    private function assertRefreshTokenRepositoryStoreRefreshToken(
        MockInterface $refreshTokenRepository,
        JWT $refreshToken
    ): self {
        $refreshTokenRepository
            ->shouldHaveReceived('storeRefreshToken')
            ->with($refreshToken)
            ->once();

        return $this;
    }

    /**
     * @param JWT|null $jwt
     *
     * @return JWTFactory|MockInterface
     */
    protected function createJWTFactory(JWT $jwt = null): JWTFactory
    {
        return Mockery::spy(JWTFactory::class)
            ->shouldReceive('createJWT')
            ->andReturn($jwt ?: $this->createJWT())
            ->getMock();
    }

    /**
     * @return EventFactory
     */
    private function createEventFactory(): EventFactory
    {
        return Mockery::spy(EventFactory::class);
    }

    /**
     * @param EventFactory|MockInterface $eventFactory
     * @param Login                      $login
     * @param string                     $guardName
     * @param Authenticatable            $user
     * @param bool                       $remember
     *
     * @return $this
     */
    private function mockEventFactoryCreateLoginEvent(
        MockInterface $eventFactory,
        Login $login,
        string $guardName,
        Authenticatable $user,
        bool $remember
    ): self {
        $eventFactory
            ->shouldReceive('createLoginEvent')
            ->with($guardName, $user, $remember)
            ->andReturn($login);

        return $this;
    }

    /**
     * @param EventFactory|MockInterface $eventFactory
     * @param Logout                     $logout
     * @param string                     $guardName
     * @param Authenticatable            $user
     *
     * @return $this
     */
    private function mockEventFactoryCreateLogoutEvent(
        MockInterface $eventFactory,
        Logout $logout,
        string $guardName,
        Authenticatable $user
    ): self {
        $eventFactory
            ->shouldReceive('createLogoutEvent')
            ->with($guardName, $user)
            ->andReturn($logout);

        return $this;
    }
}
