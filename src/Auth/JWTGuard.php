<?php

namespace SPie\LaravelJWT\Auth;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\JWTGuard as JWTGuardContract;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlockList;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\JWTException;
use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTHandler;
use Symfony\Component\HttpFoundation\Response;

final class JWTGuard implements JWTGuardContract
{
    use GuardHelpers;

    private string $name;

    private JWTHandler $jwtHandler;

    private Request $request;

    private JWTGuardConfig $jwtGuardConfig;

    private TokenProvider $accessTokenProvider;

    private TokenProvider $refreshTokenProvider;

    private RefreshTokenRepository $refreshTokenRepository;

    private ?TokenBlockList $tokenBlockList;

    private ?JWT $accessToken;

    private ?JWT $refreshToken;

    private EventFactory $eventFactory;

    private ?Dispatcher $eventDispatcher;

    public function __construct(
        string $name,
        JWTHandler $jwtHandler,
        UserProvider $provider,
        Request $request,
        JWTGuardConfig $jwtGuardConfig,
        TokenProvider $accessTokenProvider,
        TokenProvider $refreshTokenProvider,
        RefreshTokenRepository $refreshTokenRepository,
        EventFactory $eventFactory,
        TokenBlockList $tokenBlockList = null,
        Dispatcher $eventDispatcher = null
    ) {
        $this->name = $name;
        $this->jwtHandler = $jwtHandler;
        $this->provider = $provider;
        $this->request = $request;
        $this->jwtGuardConfig = $jwtGuardConfig;
        $this->accessTokenProvider = $accessTokenProvider;
        $this->refreshTokenProvider = $refreshTokenProvider;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->eventFactory = $eventFactory;
        $this->tokenBlockList = $tokenBlockList;
        $this->eventDispatcher = $eventDispatcher;

        $this->accessToken = null;
        $this->refreshToken = null;
    }

    private function setAccessToken(?JWT $accessToken): JWTGuard
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function getAccessToken(): ?JWT
    {
        return $this->accessToken;
    }

    private function setRefreshToken(?JWT $refreshToken): JWTGuard
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    public function getRefreshToken(): ?JWT
    {
        return $this->refreshToken;
    }

    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;
    }

    public function user(): ?Authenticatable
    {
        if ($this->user) {
            return $this->user;
        }

        $user = $this->authenticateWithAccessToken($this->request);
        if (!$user) {
            return $this->authenticateWithRefreshToken($this->request);
        }

        return $user;
    }

    private function authenticateWithAccessToken(Request $request): ?JWTAuthenticatable
    {
        $accessToken = $this->getAccessTokenFromRequest($request);
        if (!$accessToken) {
            return null;
        }

        $user = $this->getUserByJWT($accessToken);
        if (!$user) {
            return null;
        }

        $this
            ->setAccessToken($accessToken)
            ->setRefreshToken($this->getRefreshTokenFromRequest($this->request))
            ->setUser($user);

        return $user;
    }

    private function getAccessTokenFromRequest(Request $request): ?JWT
    {
        $accessToken = $this->accessTokenProvider->getRequestToken($request);
        if (empty($accessToken)) {
            return null;
        }

        if ($this->tokenBlockList && $this->tokenBlockList->isRevoked($accessToken)) {
            return null;
        }

        $accessJwt = $this->getJWT($accessToken);
        if (!$accessJwt) {
            return null;
        }

        if ($this->isJWTIpAddressInvalid($accessJwt)) {
            return null;
        }

        return $accessJwt;
    }

    private function authenticateWithRefreshToken(Request $request): ?JWTAuthenticatable
    {
        $refreshToken = $this->getRefreshTokenFromRequest($request);
        if (!$refreshToken) {
            return null;
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshToken->getRefreshTokenId())) {
            return null;
        }

        $user = $this->getUserByJWT($refreshToken);
        if (!$user) {
            return null;
        }

        $this
            ->setAccessToken($this->issueAccessToken($user))
            ->setRefreshToken($refreshToken)
            ->setUser($user);

        return $user;
    }

    private function getRefreshTokenFromRequest(Request $request): ?JWT
    {
        $refreshToken = $this->refreshTokenProvider->getRequestToken($request);
        if (empty($refreshToken)) {
            return null;
        }

        $refreshJwt = $this->getJWT($refreshToken);
        if (!$refreshJwt) {
            return null;
        }

        if ($this->isJWTIpAddressInvalid($refreshJwt)) {
            return null;
        }

        return $refreshJwt;
    }

    private function getJWT(string $token): ?JWT
    {
        try {
            return $this->jwtHandler->getValidJWT($token);
        } catch (JWTException $e) {
            return null;
        }
    }

    /**
     * @return Authenticatable|JWTAuthenticatable|null
     */
    private function getUserByJWT(JWT $jwt): ?Authenticatable
    {
        return $this->provider->retrieveById($jwt->getSubject());
    }

    private function isJWTIpAddressInvalid(JWT $jwt): bool
    {
        return (
            $this->jwtGuardConfig->isIpCheckEnabled()
            && !empty($jwt->getIpAddress())
            && $jwt->getIpAddress() != $this->request->ip()
        );
    }

    public function validate(array $credentials = []): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        return ($user && $this->provider->validateCredentials($user, $credentials));
    }

    /**
     * @param Authenticatable|JWTAuthenticatable $user
     */
    public function login(Authenticatable $user, $remember = false): void
    {
        $this->setUser($user);

        $this->setAccessToken($this->issueAccessToken($user));

        if ($remember) {
            $this->setRefreshToken($this->issueRefreshToken($user));
        }

        $this->dispatchEvent($this->eventFactory->createLoginEvent($this->name, $user, $remember));
    }

    private function issueAccessToken(JWTAuthenticatable $user): JWT
    {
        return $this->jwtHandler->createJWT(
            $user->getAuthIdentifier(),
            $this->setIpAddressToClaims($user->getCustomClaims()),
            $this->jwtGuardConfig->getAccessTokenTtl()
        );
    }

    private function issueRefreshToken(JWTAuthenticatable $user): JWT
    {
        $claims = $this->createClaimsWithRefreshTokenIdentifier(
            $user->getCustomClaims(),
            $this->createRefreshTokenIdentifier($user->getAuthIdentifier())
        );

        $refreshJwt = $this->jwtHandler->createJWT(
            $user->getAuthIdentifier(),
            $this->jwtGuardConfig->isIpCheckEnabled()
                ? $this->setIpAddressToClaims($claims)
                : $claims,
            $this->jwtGuardConfig->getRefreshTokenTtl()
        );

        $this->refreshTokenRepository->storeRefreshToken($refreshJwt);

        return $refreshJwt;
    }

    private function createClaimsWithRefreshTokenIdentifier(array $claims, string $refreshTokenId): array
    {
        return \array_merge(
            $claims,
            [
                JWT::CUSTOM_CLAIM_REFRESH_TOKEN => $refreshTokenId
            ]
        );
    }

    private function setIpAddressToClaims(array $claims): array
    {
        $ipAddress = $this->request->ip();
        if (!empty($ipAddress)) {
            $claims[JWT::CUSTOM_CLAIM_IP_ADDRESS] = $ipAddress;
        }

        return $claims;
    }

    public function logout(): JWTGuardContract
    {
        if (!$this->user()) {
            throw new AuthenticationException();
        }

        if ($this->getAccessToken() && $this->tokenBlockList) {
            $this->tokenBlockList->revoke($this->getAccessToken());
        }

        if ($this->getRefreshToken()) {
            $this->refreshTokenRepository->revokeRefreshToken($this->getRefreshToken()->getRefreshTokenId());
        }

        $this
            ->dispatchEvent($this->eventFactory->createLogoutEvent($this->name, $this->user()))
            ->setAccessToken(null)
            ->setRefreshToken(null)
            ->user = null;

        return $this;
    }

    public function attempt(array $credentials = [], $remember = false): bool
    {
        $this->dispatchEvent($this->eventFactory->createAttemptingEvent($this->name, $credentials, $remember));

        $user = $this->provider->retrieveByCredentials($credentials);

        if (!($user && $this->provider->validateCredentials($user, $credentials))) {
            $this->dispatchEvent($this->eventFactory->createFailedEvent($this->name, $user, $credentials));

            return false;
        }

        $this->login($user, $remember);

        return true;
    }

    public function once(array $credentials = []): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if (!($user && $this->provider->validateCredentials($user, $credentials))) {
            return false;
        }

        $this->user = $user;

        return true;
    }

    public function loginUsingId($id, $remember = false)
    {
        $user = $this->provider->retrieveById($id);
        if (!$user) {
            return false;
        }

        $this->login($user, $remember);

        return $user;
    }

    /**
     * @param mixed $id
     *
     * @return bool|Authenticatable|null
     */
    public function onceUsingId($id)
    {
        $this->user = $this->provider->retrieveById($id);
        if (!$this->user) {
            return false;
        }

        return $this->user;
    }

    public function viaRemember(): bool
    {
        return !empty($this->getRefreshToken());
    }

    public function returnTokens(Response $response): Response
    {
        if ($this->getAccessToken()) {
            $response = $this->accessTokenProvider->setResponseToken($response, $this->getAccessToken()->getJWT());
        }

        if ($this->getRefreshToken()) {
            $response = $this->refreshTokenProvider->setResponseToken($response, $this->getRefreshToken()->getJWT());
        }

        return $response;
    }

    private function createRefreshTokenIdentifier(string $subject): string
    {
        return \md5($subject . (new \DateTimeImmutable())->getTimestamp() . \mt_rand());
    }

    /**
     * @param mixed $event
     */
    private function dispatchEvent($event): JWTGuard
    {
        $this->eventDispatcher && $this->eventDispatcher->dispatch($event);

        return $this;
    }
}
