<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
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
use SPie\LaravelJWT\Contracts\Validator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

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
     * @param JWTGuard|MockInterface $jwtGuard
     * @param bool                   $isGuest
     *
     * @return $this
     */
    private function mockJWTGuardGuest(MockInterface $jwtGuard, bool $isGuest): self
    {
        $jwtGuard
            ->shouldReceive('guest')
            ->andReturn($isGuest);

        return $this;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     * @param Response               $response
     *
     * @return $this
     */
    private function mockJWTGuardReturnTokens(MockInterface $jwtGuard, Response $response): self
    {
        $jwtGuard
            ->shouldReceive('returnTokens')
            ->with($response)
            ->andReturn($response);

        return $this;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     * @param Response               $response
     *
     * @return $this
     */
    private function assertJWTGuardReturnTokens(MockInterface $jwtGuard, Response $response): self
    {
        $jwtGuard
            ->shouldHaveReceived('returnTokens')
            ->with($response)
            ->once();

        return $this;
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
     * @param string            $token
     *
     * @return $this
     */
    private function mockJWTGetJWT(MockInterface $jwt, string $token): self
    {
        $jwt
            ->shouldReceive('getJWT')
            ->andReturn($token);

        return $this;
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
     * @param DataSet|null   $headers
     * @param DataSet|null   $claims
     * @param Signature|null $signature
     *
     * @return Plain
     */
    private function createPlainToken(DataSet $headers = null, DataSet $claims = null, Signature $signature = null): Plain
    {
        return new Plain(
            $headers ?: $this->createDataSet(),
            $claims ?: $this->createDataSet(),
            $signature ?: $this->createSignature()
        );
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
    protected function createBuilder(): Builder
    {
        $builder = Mockery::spy(Builder::class);

        return $builder
            ->shouldReceive('issuedBy')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('relatedTo')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('issuedAt')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('expiresAt')
            ->andReturn($builder)
            ->getMock()
            ->shouldReceive('withClaim')
            ->andReturn($builder)
            ->getMock();
    }

    /**
     * @param Builder|MockInterface $builder
     * @param Token                 $token
     * @param Signer                $signer
     * @param Key                   $key
     *
     * @return $this
     */
    private function mockBuilderGetToken(MockInterface $builder, Token $token, Signer $signer, Key $key): self
    {
        $builder
            ->shouldReceive('getToken')
            ->with($signer, $key)
            ->andReturn($token);

        return $this;
    }

    /**
     * @return Parser|MockInterface
     */
    protected function createParser(): Parser
    {
        return Mockery::spy(Parser::class);
    }

    /**
     * @param MockInterface $parser
     * @param Token         $token
     * @param string        $jwt
     *
     * @return $this
     */
    private function mockParserParse(MockInterface $parser, $token, string $jwt): self
    {
        $expectation = $parser
            ->shouldReceive('parse')
            ->with($jwt);

        if ($token instanceof \Exception) {
            $expectation->andThrow($token);

            return $this;
        }

        $expectation->andReturn($token);

        return $this;
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
     * @return JWTFactory|MockInterface
     */
    protected function createJWTFactory(): JWTFactory
    {
        return Mockery::spy(JWTFactory::class);
    }

    /**
     * @param JWTFactory|MockInterface $jwtFactory
     * @param JWT                      $jwt
     * @param Token                    $token
     *
     * @return $this
     */
    private function mockJWTFactoryCreateJWT(MockInterface $jwtFactory, JWT $jwt, Token $token): self
    {
        $jwtFactory
            ->shouldReceive('createJWT')
            ->with($token)
            ->andReturn($jwt);

        return $this;
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

    /**
     * @return Validator|MockInterface
     */
    private function createValidator(): Validator
    {
        return Mockery::spy(Validator::class);
    }

    /**
     * @param Validator|MockInterface $validator
     * @param bool                    $valid
     * @param Token                   $token
     *
     * @return $this
     */
    private function mockValidatorValidate(MockInterface $validator, bool $valid, Token $token): self
    {
        $validator
            ->shouldReceive('validate')
            ->with($token)
            ->andReturn($valid);

        return $this;
    }

    /**
     * @return Key|MockInterface
     */
    private function createKey(): Key
    {
        return Mockery::spy(Key::class);
    }

    /**
     * @param array  $data
     * @param string $encoded
     *
     * @return DataSet
     */
    private function createDataSet(array $data = [], string $encoded = ''): DataSet
    {
        return new DataSet($data, $encoded);
    }

    /**
     * @param string|null $hash
     * @param string|null $encoded
     *
     * @return Signature
     */
    private function createSignature(string $hash = null, string $encoded = null): Signature
    {
        return new Signature($hash ?: $this->getFaker()->sha256, $encoded ?: $this->getFaker()->sha256);
    }

    /**
     * @param Signer|null $signer
     * @param Key|null    $key
     *
     * @return Configuration|MockInterface
     */
    private function createConfiguration(Signer $signer = null, Key $key = null): Configuration
    {
        return Configuration::forSymmetricSigner(
            $signer ?: $this->createSigner(),
            $key ?: $this->createKey()
        );
    }
}
