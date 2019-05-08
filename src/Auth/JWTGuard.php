<?php

namespace SPie\LaravelJWT\Auth;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\JWTGuard as JWTGuardContract;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\JWTException;
use SPie\LaravelJWT\Exceptions\MissingRefreshTokenProviderException;
use SPie\LaravelJWT\Exceptions\MissingRefreshTokenRepositoryException;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class JWTGuard
 *
 * @package SPie\LaravelJWT\Auth
 */
final class JWTGuard implements JWTGuardContract
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
    private function getJWTHandler(): JWTHandler
    {
        return $this->jwtHandler;
    }

    /**
     * @return UserProvider
     */
    private function getProvider(): UserProvider
    {
        return $this->provider;
    }

    /**
     * @return Request
     */
    private function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * @return TokenProvider
     */
    private function getAccessTokenProvider(): TokenProvider
    {
        return $this->accessTokenProvider;
    }

    /**
     * @return int
     */
    private function getAccessTokenTtl(): int
    {
        return $this->accessTokenTtl;
    }

    /**
     * @return null|TokenBlacklist
     */
    private function getTokenBlacklist(): ?TokenBlacklist
    {
        return $this->tokenBlacklist;
    }

    /**
     * @return TokenProvider|null
     */
    private function getRefreshTokenProvider(): ?TokenProvider
    {
        return $this->refreshTokenProvider;
    }

    /**
     * @return int|null
     */
    private function getRefreshTokenTtl(): ?int
    {
        return $this->refreshTokenTtl;
    }

    /**
     * @return null|RefreshTokenRepository
     */
    private function getRefreshTokenRepository(): ?RefreshTokenRepository
    {
        return $this->refreshTokenRepository;
    }

    /**
     * @param JWT|null $accessToken
     *
     * @return JWTGuard
     */
    private function setAccessToken(?JWT $accessToken): JWTGuard
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
    private function setRefreshToken(?JWT $refreshToken): JWTGuard
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
        if (!empty($token)) {
            return $this->authenticateWithAccessToken($token);
        }

        if ($this->getRefreshTokenProvider()) {
            return $this->authenticateWithRefreshToken();
        }

        return null;
    }

    /**
     * @param string $token
     *
     * @return Authenticatable|null
     *
     * @throws \Exception
     */
    private function authenticateWithAccessToken(string $token): ?Authenticatable
    {
        if ($this->getTokenBlacklist() && $this->getTokenBlacklist()->isRevoked($token)) {
            return null;
        }

        $jwt = $this->getJWT($token);
        if (empty($jwt)) {
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
     * @return Authenticatable|null
     *
     * @throws \Exception
     */
    private function authenticateWithRefreshToken(): ?Authenticatable
    {
        $token = $this->getRefreshTokenProvider()->getRequestToken($this->getRequest());
        if (empty($token)) {
            return null;
        }

        $jwt = $this->getJWT($token);
        if (empty($jwt)) {
            return null;
        }

        $user = $this->getUserByJWT($jwt);
        if ($user) {
            $this
                ->setRefreshToken($jwt)
                ->setUser($user);
        }

        return $user;
    }

    /**
     * @param string $token
     *
     * @return JWT|null
     *
     * @throws \Exception
     */
    private function getJWT(string $token): ?JWT
    {
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

        return $jwt;
    }

    /**
     * @param JWT $jwt
     *
     * @return Authenticatable|JWTAuthenticatable|null
     */
    private function getUserByJWT(JWT $jwt): ?Authenticatable
    {
        return $this->getProvider()->retrieveById($jwt->getSubject());
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
     * @return JWTGuardContract
     *
     * @throws AuthorizationException
     * @throws \Exception
     */
    public function login(array $credentials = []): JWTGuardContract
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
     * @return JWTGuardContract
     */
    public function logout(): JWTGuardContract
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

        $claims = $this->createClaimsWithRefreshTokenIdentifier(
            $user->getCustomClaims(),
            $this->createRefreshTokenIdentifier($user->getAuthIdentifier())
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
        $refreshJWT = $this->getValidRefreshToken();

        $user = $this->getUserByJWT($refreshJWT);
        if (!$user) {
            throw new NotAuthenticatedException();
        }

        $this
            ->setAccessToken(
                $this->getJWTHandler()->createJWT(
                    $user->getAuthIdentifier(),
                    $this->createClaimsWithRefreshTokenIdentifier(
                        $user->getCustomClaims(),
                        $refreshJWT->getRefreshTokenId()
                    ),
                    $this->getAccessTokenTtl())
            )
            ->setUser($user);

        //TODO refresh access token event

        return $this->getAccessToken();
    }

    /**
     * @return JWT
     */
    private function getValidRefreshToken(): JWT
    {
        if (empty($this->getRefreshToken())) {
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
        } else {
            $refreshJWT = $this->getRefreshToken();
        }

        if (empty($refreshJWT->getRefreshTokenId())) {
            throw new NotAuthenticatedException();
        }

        return $refreshJWT;
    }

    /**
     * @param array  $claims
     * @param string $refreshTokenId
     *
     * @return array
     */
    private function createClaimsWithRefreshTokenIdentifier(array $claims, string $refreshTokenId): array
    {
        return \array_merge(
            $claims,
            [
                JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshTokenId
            ]
        );
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
     * @throws MissingRefreshTokenProviderException
     */
    public function returnRefreshToken(Response $response): Response
    {
        if (!$this->getRefreshTokenProvider()) {
            throw new MissingRefreshTokenProviderException();
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
    private function createRefreshTokenIdentifier(string $subject): string
    {
        return \md5($subject . (new \DateTimeImmutable())->getTimestamp() . \mt_rand());
    }
}
