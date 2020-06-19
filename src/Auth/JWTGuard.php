<?php

namespace SPie\LaravelJWT\Auth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\EventFactory;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\JWTGuard as JWTGuardContract;
use SPie\LaravelJWT\Contracts\RefreshTokenRepository;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Events\RefreshAccessToken;
use SPie\LaravelJWT\Exceptions\JWTException;
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
     * @var string
     */
    private string $name;

    /**
     * @var JWTHandler
     */
    private JWTHandler $jwtHandler;

    /**
     * @var Request
     */
    private Request $request;

    /**
     * @var JWTGuardConfig
     */
    private JWTGuardConfig $jwtGuardConfig;

    /**
     * @var TokenProvider
     */
    private TokenProvider $accessTokenProvider;

    /**
     * @var TokenProvider
     */
    private TokenProvider $refreshTokenProvider;

    /**
     * @var RefreshTokenRepository
     */
    private RefreshTokenRepository $refreshTokenRepository;

    /**
     * @var TokenBlacklist|null
     */
    private ?TokenBlacklist $tokenBlacklist;

    /**
     * @var JWT|null
     */
    private ?JWT $accessToken;

    /**
     * @var JWT|null
     */
    private ?JWT $refreshToken;

    /**
     * @var EventFactory
     */
    private EventFactory $eventFactory;

    /**
     * @var Dispatcher|null
     */
    private ?Dispatcher $eventDispatcher;

    /**
     * JWTGuard constructor.
     *
     * @param string                 $name
     * @param JWTHandler             $jwtHandler
     * @param UserProvider           $provider
     * @param Request                $request
     * @param JWTGuardConfig         $jwtGuardConfig
     * @param TokenProvider          $accessTokenProvider
     * @param TokenProvider          $refreshTokenProvider
     * @param RefreshTokenRepository $refreshTokenRepository
     * @param EventFactory           $eventFactory
     * @param TokenBlacklist|null    $tokenBlacklist
     * @param Dispatcher|null        $eventDispatcher
     */
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
        TokenBlacklist $tokenBlacklist = null,
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
        $this->tokenBlacklist = $tokenBlacklist;
        $this->eventDispatcher = $eventDispatcher;

        $this->accessToken = null;
        $this->refreshToken = null;
    }

    /**
     * @return string
     */
    private function getName(): string
    {
        return $this->name;
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
     * @return JWTGuardConfig
     */
    private function getJwtGuardConfig(): JWTGuardConfig
    {
        return $this->jwtGuardConfig;
    }

    /**
     * @return TokenProvider
     */
    private function getAccessTokenProvider(): TokenProvider
    {
        return $this->accessTokenProvider;
    }

    /**
     * @return TokenProvider
     */
    private function getRefreshTokenProvider(): TokenProvider
    {
        return $this->refreshTokenProvider;
    }

    /**
     * @return RefreshTokenRepository
     */
    private function getRefreshTokenRepository(): RefreshTokenRepository
    {
        return $this->refreshTokenRepository;
    }

    /**
     * @return EventFactory
     */
    private function getEventFactory(): EventFactory
    {
        return $this->eventFactory;
    }

    /**
     * @return null|TokenBlacklist
     */
    private function getTokenBlacklist(): ?TokenBlacklist
    {
        return $this->tokenBlacklist;
    }

    /**
     * @return Dispatcher|null
     */
    private function getEventDispatcher(): ?Dispatcher
    {
        return $this->eventDispatcher;
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

        $user = $this->authenticateWithAccessToken($this->getRequest());
        if (!$user) {
            return $this->authenticateWithRefreshToken($this->getRequest());
        }

        return $user;
    }

    /**
     * @param Request $request
     *
     * @return JWTAuthenticatable|null
     */
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
            ->setRefreshToken($this->getRefreshTokenFromRequest($this->getRequest()))
            ->setUser($user);

        return $user;
    }

    /**
     * @param Request $request
     *
     * @return JWT|null
     */
    private function getAccessTokenFromRequest(Request $request): ?JWT
    {
        $accessToken = $this->getAccessTokenProvider()->getRequestToken($request);
        if (empty($accessToken)) {
            return null;
        }

        if ($this->getTokenBlacklist() && $this->getTokenBlacklist()->isRevoked($accessToken)) {
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

    /**
     * @param Request $request
     *
     * @return JWTAuthenticatable|null
     */
    private function authenticateWithRefreshToken(Request $request): ?JWTAuthenticatable
    {
        $refreshToken = $this->getRefreshTokenFromRequest($request);
        if (!$refreshToken) {
            return null;
        }

        if ($this->getRefreshTokenRepository()->isRefreshTokenRevoked($refreshToken->getRefreshTokenId())) {
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

    /**
     * @param Request $request
     *
     * @return JWT|null
     */
    private function getRefreshTokenFromRequest(Request $request): ?JWT
    {
        $refreshToken = $this->getRefreshTokenProvider()->getRequestToken($request);
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
            return $this->getJWTHandler()->getValidJWT($token);
        } catch (JWTException $e) {
            return null;
        }
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
     * @param JWT $jwt
     *
     * @return bool
     */
    private function isJWTIpAddressInvalid(JWT $jwt): bool
    {
        return (
            $this->getJWTGuardConfig()->isIpCheckEnabled()
            && !empty($jwt->getIpAddress())
            && $jwt->getIpAddress() != $this->getRequest()->ip()
        );
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
     * @param Authenticatable|JWTAuthenticatable $user
     * @param bool                               $remember
     *
     * @return void
     */
    public function login(Authenticatable $user, $remember = false)
    {
        $this->setUser($user);

        $this->setAccessToken($this->issueAccessToken($user));

        if ($remember) {
            $this->setRefreshToken($this->issueRefreshToken($user));
        }

        $this->dispatchEvent($this->getEventFactory()->createLoginEvent($this->getName(), $user, $remember));
    }

    /**
     * @param JWTAuthenticatable $user
     *
     * @return JWT
     *
     * @throws \Exception
     */
    private function issueAccessToken(JWTAuthenticatable $user): JWT
    {
        return $this->getJWTHandler()->createJWT(
            $user->getAuthIdentifier(),
            $this->setIpAddressToClaims($user->getCustomClaims()),
            $this->getJWTGuardConfig()->getAccessTokenTtl()
        );
    }

    /**
     * @param JWTAuthenticatable $user
     *
     * @return JWT
     */
    public function issueRefreshToken(JWTAuthenticatable $user): JWT
    {
        $claims = $this->createClaimsWithRefreshTokenIdentifier(
            $user->getCustomClaims(),
            $this->createRefreshTokenIdentifier($user->getAuthIdentifier())
        );

        $refreshJwt = $this->getJWTHandler()->createJWT(
            $user->getAuthIdentifier(),
            $this->getJwtGuardConfig()->isIpCheckEnabled()
                ? $this->setIpAddressToClaims($claims)
                : $claims,
            $this->getJWTGuardConfig()->getRefreshTokenTtl()
        );

        $this->getRefreshTokenRepository()->storeRefreshToken($refreshJwt);

        return $refreshJwt;
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
     * @param array $claims
     *
     * @return array
     */
    private function setIpAddressToClaims(array $claims): array
    {
        $ipAddress = $this->getRequest()->ip();
        if (!empty($ipAddress)) {
            $claims[JWT::CUSTOM_CLAIM_IP_ADDRESS] = $ipAddress;
        }

        return $claims;
    }

    /**
     * @return JWTGuardContract
     */
    public function logout(): JWTGuardContract
    {
        if (!$this->user()) {
            throw new NotAuthenticatedException();
        }

        if ($this->getAccessToken() && $this->getTokenBlacklist()) {
            $this->getTokenBlacklist()->revoke($this->getAccessToken());
        }

        if ($this->getRefreshToken()) {
            $this->getRefreshTokenRepository()->revokeRefreshToken($this->getRefreshToken()->getRefreshTokenId());
        }

        $this
            ->dispatchEvent($this->getEventFactory()->createLogoutEvent($this->getName(), $this->user()))
            ->setAccessToken(null)
            ->setRefreshToken(null)
            ->user = null;

        return $this;
    }

    /**
     * @param array $credentials
     * @param bool  $remember
     *
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->dispatchEvent($this->getEventFactory()->createAttemptingEvent($this->getName(), $credentials, $remember));

        $user = $this->getProvider()->retrieveByCredentials($credentials);

        if (!($user && $this->getProvider()->validateCredentials($user, $credentials))) {
            $this->dispatchEvent($this->getEventFactory()->createFailedEvent($this->getName(), $user, $credentials));

            return false;
        }

        $this->login($user, $remember);

        return true;
    }

    /**
     * @param array $credentials
     *
     * @return bool
     */
    public function once(array $credentials = [])
    {
        $user = $this->getProvider()->retrieveByCredentials($credentials);
        if (!($user && $this->getProvider()->validateCredentials($user, $credentials))) {
            return false;
        }

        $this->user = $user;

        return true;
    }

    public function loginUsingId($id, $remember = false)
    {
        $user = $this->getProvider()->retrieveById($id);
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
        $this->user = $this->getProvider()->retrieveById($id);
        if (!$this->user) {
            return false;
        }

        return $this->user;
    }

    /**
     * @return bool
     */
    public function viaRemember()
    {
        return !empty($this->getRefreshToken());
    }
//
//    /**
//     * @return JWT
//     *
//     * @throws \Exception
//     */
//    public function refreshAccessToken(): JWT
//    {
//        $refreshJWT = $this->getValidRefreshToken();
//
//        $user = $this->getUserByJWT($refreshJWT);
//        if (!$user) {
//            throw new NotAuthenticatedException();
//        }
//
//        $this
//            ->setAccessToken(
//                $this->getJWTHandler()->createJWT(
//                    $user->getAuthIdentifier(),
//                    $this->createClaimsWithRefreshTokenIdentifier(
//                        $this->setIpAddressToClaims($user->getCustomClaims()),
//                        $refreshJWT->getRefreshTokenId()
//                    ),
//                    $this->getAccessTokenTtl())
//            )
//            ->setUser($user);
//
//        $this->dispatchEvent(new RefreshAccessToken($this->user(), $this->getAccessToken(), $refreshJWT));
//
//        return $this->getAccessToken();
//    }
//
//    /**
//     * @return JWT
//     */
//    private function getValidRefreshToken(): JWT
//    {
//        if (empty($this->getRefreshToken())) {
//            $token = $this->getRefreshTokenProvider()->getRequestToken($this->getRequest());
//            if (empty($token)) {
//                throw new NotAuthenticatedException();
//            }
//
//            if ($this->getTokenBlacklist()->isRevoked($token)) {
//                throw new NotAuthenticatedException();
//            }
//
//            try {
//                $refreshJWT = $this->getJWTHandler()->getValidJWT($token);
//            } catch (JWTException $e) {
//                throw new NotAuthenticatedException();
//            }
//        } else {
//            $refreshJWT = $this->getRefreshToken();
//        }
//
//        if (empty($refreshJWT->getRefreshTokenId())) {
//            throw new NotAuthenticatedException();
//        }
//
//        return $refreshJWT;
//    }

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

    /**
     * @param mixed $event
     *
     * @return JWTGuard
     */
    private function dispatchEvent($event): JWTGuard
    {
        if ($this->getEventDispatcher()) {
            $this->getEventDispatcher()->dispatch($event);
        }

        return $this;
    }
}
