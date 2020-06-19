<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Mockery;
use Mockery\MockInterface;
use SPie\LaravelJWT\Auth\JWTGuardConfig;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTHandler;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Request;

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
     * @param JWTHandler|MockInterface $jwtHandler
     * @param JWT|\Exception           $jwt
     * @param string                   $token
     *
     * @return $this
     */
    private function mockJWTHandlerGetValidJWT(MockInterface $jwtHandler, $jwt, string $token): self
    {
        $jwtHandler
            ->shouldReceive('getValidJWT')
            ->with($token)
            ->andThrow($jwt);

        return $this;
    }

    /**
     * @return JWT|MockInterface
     */
    protected function createJWT(): JWT
    {
        return Mockery::spy(JWT::class);
    }

    /**
     * @param JWT|MockInterface $jwt
     * @param string            $subject
     *
     * @return $this
     */
    private function mockJWTGetSubject(MockInterface $jwt, string $subject): self
    {
        $jwt
            ->shouldReceive('getSubject')
            ->andReturn($subject);

        return $this;
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
     * @param JWT|MockInterface $jwt
     * @param string            $refreshTokenId
     *
     * @return $this
     */
    private function mockJWTGetRefreshTokenId(MockInterface $jwt, string $refreshTokenId): self
    {
        $jwt
            ->shouldReceive('getRefreshTokenId')
            ->andReturn($refreshTokenId);

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
     * @param bool                                 $isRevoked
     * @param string                               $refreshTokenId
     *
     * @return $this
     */
    private function mockRefreshTokenRepositoryIsRefreshTokenRevoked(
        MockInterface $refreshTokenRepository,
        bool $isRevoked,
        string $refreshTokenId
    ): self {
        $refreshTokenRepository
            ->shouldReceive('isRefreshTokenRevoked')
            ->with($refreshTokenId)
            ->andReturn($isRevoked);

        return $this;
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

    /**
     * @param EventFactory|MockInterface $eventFactory
     * @param Attempting                 $attempting
     * @param string                     $guardName
     * @param array                      $credentials
     * @param bool                       $remember
     *
     * @return $this
     */
    private function mockEventFactoryCreateAttemptingEvent(
        MockInterface $eventFactory,
        Attempting $attempting,
        string $guardName,
        array $credentials,
        bool $remember
    ): self {
        $eventFactory
            ->shouldReceive('createAttemptingEvent')
            ->with($guardName, $credentials, $remember)
            ->andReturn($attempting);

        return $this;
    }

    /**
     * @param EventFactory|MockInterface $eventFactory
     * @param Failed                     $failed
     * @param string                     $guardName
     * @param Authenticatable|null       $user
     * @param array                      $credentials
     *
     * @return $this
     */
    private function mockEventFactoryCreateFailedEvent(
        MockInterface $eventFactory,
        Failed $failed,
        string $guardName,
        ?Authenticatable $user,
        array $credentials
    ): self {
        $eventFactory
            ->shouldReceive('createFailedEvent')
            ->with($guardName, $user, $credentials)
            ->andReturn($failed);

        return $this;
    }

    /**
     * @param bool|null $withIpCheck
     * @param int|null  $accessTokenTtl
     * @param int|null  $refreshTokenTtl
     *
     * @return JWTGuardConfig
     */
    private function createJWTGuardConfig(
        bool $withIpCheck = null,
        int $accessTokenTtl = null,
        int $refreshTokenTtl = null
    ): JWTGuardConfig {
        return new JWTGuardConfig(
            $accessTokenTtl ?? $this->getFaker()->numberBetween(),
            $refreshTokenTtl ?? $this->getFaker()->numberBetween(),
            $withIpCheck ?? $this->getFaker()->boolean,
        );
    }

    /**
     * @return Authenticatable|MockInterface
     */
    private function createAuthenticatable(): Authenticatable
    {
        return Mockery::spy(Authenticatable::class);
    }

    /**
     * @return TokenProvider|MockInterface
     */
    private function createTokenProvider(): TokenProvider
    {
        return Mockery::spy(TokenProvider::class);
    }

    /**
     * @param TokenProvider|MockInterface $tokenProvider
     * @param string|null                 $token
     * @param Request                     $request
     *
     * @return $this
     */
    private function mockTokenProviderGetRequestToken(MockInterface $tokenProvider, ?string $token, Request $request): self
    {
        $tokenProvider
            ->shouldReceive('getRequestToken')
            ->with($request)
            ->andReturn($token);

        return $this;
    }
}
