<?php

namespace SPie\LaravelJWT\Auth;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\TokenBlacklist;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\JWTException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTHandler;

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
    private $tokenProvider;

    /**
     * @var TokenBlacklist|null
     */
    private $tokenBlacklist;

    /**
     * @var JWT
     */
    private $jwt;

    //TODO events dispatcher

    /**
     * JWTGuard constructor.
     *
     * @param JWTHandler          $jwtHandler
     * @param UserProvider        $provider
     * @param Request             $request
     * @param TokenProvider       $tokenProvider
     * @param TokenBlacklist|null $tokenBlacklist
     */
    public function __construct(
        JWTHandler $jwtHandler,
        UserProvider $provider,
        Request $request,
        TokenProvider $tokenProvider,
        TokenBlacklist $tokenBlacklist = null
    )
    {
        $this->jwtHandler = $jwtHandler;
        $this->provider = $provider;
        $this->request = $request;
        $this->tokenProvider = $tokenProvider;
        $this->tokenBlacklist = $tokenBlacklist;
    }

    /**
     * @return JWTHandler
     */
    protected function getJwtHandler(): JWTHandler {
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
    protected function getTokenProvider(): TokenProvider
    {
        return $this->tokenProvider;
    }

    /**
     * @return null|TokenBlacklist
     */
    protected function getTokenBlacklist(): ?TokenBlacklist
    {
        return $this->tokenBlacklist;
    }

    /**
     * @param JWT|null $jwt
     *
     * @return JWTGuard
     */
    public function setJWT(?JWT $jwt): JWTGuard
    {
        $this->jwt = $jwt;

        return $this;
    }

    /**
     * @return JWT|null
     */
    public function getJWT(): ?JWT
    {
        return $this->jwt;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     *
     * @throws \Exception
     */
    public function user(): ?Authenticatable
    {
        if ($this->user) {
            return $this->user;
        }

        $token = $this->getTokenProvider()->getRequestToken($this->getRequest());
        if (empty($token)) {
            return null;
        }

        if ($this->getTokenBlacklist() && $this->getTokenBlacklist()->isRevoked($token)) {
            return null;
        }

        try {
            $jwt = $this->getJwtHandler()->getValidJWT($token);
        } catch (JWTException $e) {
            return null;
        }

        $user = $this->getUserByJWT($jwt);
        if ($user) {
            $this->setJWT($jwt);
        }

        $this->user = $user;

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
     * @return Authenticatable|null
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
    public function issueJWT(JWTAuthenticatable $user): JWT
    {
        return $this->getJwtHandler()->createJWT($user->getAuthIdentifier(), $user->getCustomClaims());
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
                ->setJWT(null)
                ->user = null;

            throw new AuthorizationException();
        }

        //TODO login event

        $this
            ->setJWT($this->issueJWT($user))
            ->setUser($user);

        return $this;
    }

    /**
     * @return JWTGuard
     */
    public function logout(): JWTGuard
    {
        if ($this->getTokenBlacklist() && $this->getJWT()) {
            $this->getTokenBlacklist()->revoke($this->getJWT());
        }

        $this
            ->setJWT(null)
            ->user = null;

        return $this;
    }
}
