<?php

namespace SPie\LaravelJWT\Auth;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\JWTException;
use SPie\LaravelJWT\Exceptions\MissingRefreshTokenRepositoryException;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class JWTGuard
 *
 * @package SPie\LaravelJWT\Auth
 */
class JWTGuard implements Guard
{

    use GuardHelpers;

    /**
     * @var JWTHandler
     */
    private $jwtHandler;

    /**
     * @var Request
     */
    private $request;

    /**
     * @var TokenProvider
     */
    private $accessTokenProvider;

    /**
     * @var int
     */
    private $accessTokenTtl;

    /**
     * @var TokenBlacklist|null
     */
    private $tokenBlacklist;

    /**
     * @var TokenProvider|null
     */
    private $refreshTokenProvider;

    /**
     * @var int|null
     */
    private $refreshTokenTtl;

    /**
     * @var RefreshTokenRepository|null
     */
    private $refreshTokenRepository;

    /**
     * @var JWT
     */
    private $accessToken;

    /**
     * @var JWT
     */
    private $refreshToken;

    //TODO events dispatcher

    /**
     * JWTGuard constructor.
     *
     * @param JWTHandler                  $jwtHandler
     * @param UserProvider                $provider
     * @param Request                     $request
     * @param TokenProvider               $accessTokenProvider
     * @param int                         $accessTokenTtl
     * @param TokenBlacklist|null         $tokenBlacklist
     * @param TokenProvider|null          $refreshTokenProvider
     * @param int|null                    $refreshTokenTtl
     * @param RefreshTokenRepository|null $refreshTokenRepository
     */
    public function __construct(
        JWTHandler $jwtHandler,
        UserProvider $provider,
        Request $request,
        TokenProvider $accessTokenProvider,
        int $accessTokenTtl,
        TokenBlacklist $tokenBlacklist = null,
        TokenProvider $refreshTokenProvider = null,
        int $refreshTokenTtl = null,
        RefreshTokenRepository $refreshTokenRepository = null
    )
    {
        $this->jwtHandler = $jwtHandler;
        $this->provider = $provider;
        $this->request = $request;
        $this->accessTokenProvider = $accessTokenProvider;
        $this->accessTokenTtl = $accessTokenTtl;
        $this->tokenBlacklist = $tokenBlacklist;
        $this->refreshTokenProvider = $refreshTokenProvider;
        $this->refreshTokenTtl = $refreshTokenTtl;
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * @return JWTHandler
     */
    protected function getJWTHandler(): JWTHandler {
        return $this->jwtHandler;
    }

    /**
     * @return Request
     */
    protected function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * @return TokenProvider
     */
    protected function getAccessTokenProvider(): TokenProvider
    {
        return $this->accessTokenProvider;
    }

    /**
     * @return int
     */
    protected function getAccessTokenTtl(): int
    {
        return $this->accessTokenTtl;
    }

    /**
     * @return null|TokenBlacklist
     */
    protected function getTokenBlacklist(): ?TokenBlacklist
    {
        return $this->tokenBlacklist;
    }

    /**
     * @return TokenProvider|null
     */
    protected function getRefreshTokenProvider(): ?TokenProvider
    {
        return $this->refreshTokenProvider;
    }

    /**
     * @return int|null
     */
    protected function getRefreshTokenTtl(): ?int
    {
        return $this->refreshTokenTtl;
    }

    /**
     * @return null|RefreshTokenRepository
     */
    protected function getRefreshTokenRepository(): ?RefreshTokenRepository
    {
        return $this->refreshTokenRepository;
    }

    /**
     * @param JWT|null $accessToken
     *
     * @return JWTGuard
     */
    protected function setAccessToken(?JWT $accessToken): JWTGuard
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * @return JWT|null
     */
    public function getAccessToken(): ?JWT
    {
        return $this->accessToken;
    }

    /**
     * @param JWT|null $refreshToken
     *
     * @return JWTGuard
     */
    protected function setRefreshToken(?JWT $refreshToken): JWTGuard
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    /**
     * @return JWT|null
     */
    public function getRefreshToken(): ?JWT
    {
        return $this->refreshToken;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return Authenticatable|JWTAuthenticatable|null
     *
     * @throws \Exception
     */
    public function user(): ?Authenticatable
    {
        if ($this->user) {
            return $this->user;
        }

        $token = $this->getAccessTokenProvider()->getRequestToken($this->getRequest());
        if (empty($token)) {
            return null;
        }

        if ($this->getTokenBlacklist() && $this->getTokenBlacklist()->isRevoked($token)) {
            return null;
        }

        try {
            $jwt = $this->getJWTHandler()->getValidJWT($token);
        } catch (JWTException $e) {
            return null;
        }

        if (
            $this->getRefreshTokenRepository()
            && !empty($jwt->getRefreshTokenId())
            && $this->getRefreshTokenRepository()->isRefreshTokenRevoked($jwt->getRefreshTokenId())
        ) {
            return null;
        }

        $user = $this->getUserByJWT($jwt);
        if ($user) {
            $this
                ->setAccessToken($jwt)
                ->setUser($user);
        }

        return $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        $user = $this->getProvider()->retrieveByCredentials($credentials);

        return ($user && $this->getProvider()->validateCredentials($user, $credentials));
    }

    /**
     * Set the current user.
     *
     * @param Authenticatable $user
     *
     * @return void
     */
    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;
    }

    /**
     * @param JWT $jwt
     *
     * @return Authenticatable|JWTAuthenticatable|null
     */
    protected function getUserByJWT(JWT $jwt): ?Authenticatable
    {
        return $this->getProvider()->retrieveById($jwt->getSubject());
    }

    /**
     * @param JWTAuthenticatable $user
     *
     * @return JWT
     *
     * @throws \Exception
     */
    public function issueAccessToken(JWTAuthenticatable $user): JWT
    {
        $this->setAccessToken(
            $this->getJWTHandler()->createJWT(
                $user->getAuthIdentifier(),
                $user->getCustomClaims(),
                $this->getAccessTokenTtl()
            )
        );

        return $this->getAccessToken();
    }

    /**
     * @param array $credentials
     *
     * @return JWTGuard
     *
     * @throws AuthorizationException
     * @throws \Exception
     */
    public function login(array $credentials = []): JWTGuard
    {
        //TODO attempt event

        $user = $this->getProvider()->retrieveByCredentials($credentials);

        if (
            !$user
            || !($user instanceof JWTAuthenticatable)
            || !$this->getProvider()->validateCredentials($user, $credentials)
        ) {
            //TODO failed event

            $this
                ->setAccessToken(null)
                ->user = null;

            throw new AuthorizationException();
        }

        //TODO login event

        $this
            ->setAccessToken($this->issueAccessToken($user))
            ->setUser($user);

        return $this;
    }

    /**
     * @return JWTGuard
     */
    public function logout(): JWTGuard
    {
        if ($this->getAccessToken()) {
            if ($this->getTokenBlacklist()) {
                $this->getTokenBlacklist()->revoke($this->getAccessToken());
            }

            if ($this->getRefreshTokenRepository() && $this->getAccessToken()->getRefreshTokenId()) {
                $this->getRefreshTokenRepository()->revokeRefreshToken($this->getAccessToken()->getRefreshTokenId());
            }
        }

        $this
            ->setAccessToken(null)
            ->setRefreshToken(null)
            ->user = null;

        //TODO logout event

        return $this;
    }

    /**
     * @return JWT
     *
     * @throws \Exception
     */
    public function issueRefreshToken(): JWT
    {
        if (!$this->getRefreshTokenRepository()) {
            throw new MissingRefreshTokenRepositoryException();
        }

        $user = $this->user();
        if (!$user || !$this->getAccessToken()) {
            throw new NotAuthenticatedException();
        }

        $claims = \array_merge(
            $user->getCustomClaims(),
            [
                JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $this->createRefreshTokenIdentifier($user->getAuthIdentifier())
            ]
        );

        $refreshJwt = $this->getJWTHandler()->createJWT($user->getAuthIdentifier(), $claims, $this->getRefreshTokenTtl());

        $this->getRefreshTokenRepository()->storeRefreshToken($refreshJwt);

        if ($this->getTokenBlacklist()) {
            $this->getTokenBlacklist()->revoke($this->getAccessToken());
        }

        $this
            ->setAccessToken(
                $this->getJWTHandler()->createJWT($user->getAuthIdentifier(), $claims, $this->getAccessTokenTtl())
            )
            ->setRefreshToken($refreshJwt);

        //TODO issue refresh token event

        return $refreshJwt;
    }

    /**
     * @return JWT
     *
     * @throws \Exception
     */
    public function refreshAccessToken(): JWT
    {
        $token = $this->getRefreshTokenProvider()->getRequestToken($this->getRequest());
        if (empty($token)) {
            throw new NotAuthenticatedException();
        }

        if ($this->getTokenBlacklist()->isRevoked($token)) {
            throw new NotAuthenticatedException();
        }

        try {
            $refreshJWT = $this->getJWTHandler()->getValidJWT($token);
        } catch (JWTException $e) {
            throw new NotAuthenticatedException();
        }

        if (empty($refreshJWT->getRefreshTokenId())) {
            throw new NotAuthenticatedException();
        }

        $user = $this->getUserByJWT($refreshJWT);
        if (!$user) {
            throw new NotAuthenticatedException();
        }

        $payload = \array_merge(
            $user->getCustomClaims(),
            [
                JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshJWT->getRefreshTokenId()
            ]
        );

        $this
            ->setAccessToken(
                $this->getJWTHandler()->createJWT($user->getAuthIdentifier(), $payload, $this->getAccessTokenTtl())
            )
            ->setUser($user);

        //TODO refresh access token event

        return $this->getAccessToken();
    }

    /**
     * @param Response $response
     *
     * @return Response
     *
     * @throws NotAuthenticatedException
     */
    public function returnAccessToken(Response $response): Response
    {
        if (empty($this->getAccessToken())) {
            throw new NotAuthenticatedException();
        }

        return $this->getAccessTokenProvider()->setResponseToken($response, $this->getAccessToken()->getJWT());
    }

    /**
     * @param Response $response
     *
     * @return Response
     *
     * @throws NotAuthenticatedException
     */
    public function returnRefreshToken(Response $response): Response
    {
        if (!$this->getRefreshTokenProvider()) {
            return $response;
        }

        if (empty($this->getRefreshToken())) {
            throw new NotAuthenticatedException();
        }

        return $this->getRefreshTokenProvider()->setResponseToken($response, $this->getRefreshToken()->getJWT());
    }

    /**
     * @param string $subject
     *
     * @return string
     *
     * @throws \Exception
     */
    protected function createRefreshTokenIdentifier(string $subject): string
    {
        return \md5($subject . (new \DateTimeImmutable())->getTimestamp() . \mt_rand());
    }
}
