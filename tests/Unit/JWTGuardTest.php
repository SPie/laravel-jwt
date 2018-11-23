<?php

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Contracts\TokenProvider;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTHandler;

/**
 * Class JWTGuardTest
 */
class JWTGuardTest extends TestCase
{

    use JWTHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUser(): void
    {
        $user = $this->createUser();

        $this->assertEquals(
            $user,
            $this->createJWTGuard(
                $this->createJWTHandler($this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $this->getFaker()->uuid,]))),
                $this->createUserProvider($user),
                new Request(),
                $this->createTokenProvider($this->createToken())
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserWithExistingUser(): void
    {
        $user = $this->createUser();
        $jwtGuard = $this->createJWTGuard();
        $jwtGuard->setUser($user);

        $this->assertEquals($user, $jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserEmptyToken(): void
    {
        $this->assertEmpty($this->createJWTGuard()->user());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testUserInvalidToken(): void
    {
        $this->assertEmpty(
            $this->createJWTGuard(
                $this->createJWTHandler()->setJWTException(new InvalidTokenException()),
                null,
                null,
                $this->createTokenProvider($this->createToken())
            )->user()
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     */
    public function testValidate(): void
    {
        $this->assertTrue(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser())->setValidCredentials(true)
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     */
    public function testValidateWithoutUser(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider()
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     */
    public function testValidateWithInvalidCredentials(): void
    {
        $this->assertFalse(
            $this->createJWTGuard(
                null,
                $this->createUserProvider($this->createUser())->setValidCredentials(false)
            )->validate([$this->getFaker()->uuid => $this->getFaker()->uuid])
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testIssueJWT(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $user->getAuthIdentifier()]));

        $this->assertEquals(
            $jwt,
            $this->createJWTGuard(
                $this->createJWTHandler($jwt),
                $this->createUserProvider($user),
                new Request(),
                $this->createTokenProvider()
            )->issueJWT($user)
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws AuthorizationException
     * @throws Exception
     */
    public function testLogin(): void
    {
        $user = $this->createUser();
        $jwt = $this->createJWT();

        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($jwt),
            $this->createUserProvider($user)->setValidCredentials(true),
            new Request(),
            $this->createTokenProvider()
        )->login([
            $this->getFaker()->uuid => $this->getFaker()->uuid,
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ]);

        $this->assertEquals($user, $jwtGuard->user());
        $this->assertEquals($jwt, $jwtGuard->getJWT());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLoginWithoutUser(): void
    {
        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($this->createJWT()),
            $this->createUserProvider(),
            new Request(),
            $this->createTokenProvider()
        );

        try {
            $jwtGuard->login([
                $this->getFaker()->uuid => $this->getFaker()->uuid,
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]);

            $this->assertTrue(false);
        } catch (AuthorizationException $e) {
            $this->assertTrue(true);
        }

        $this->assertEmpty($jwtGuard->getJWT());
        $this->assertEmpty($jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLoginWithoutJWTAuthenticatable(): void
    {
        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($this->createJWT()),
            $this->createUserProvider(
                new class implements Authenticatable {
                    public function getAuthIdentifierName() {}
                    public function getAuthIdentifier() {}
                    public function getAuthPassword() {}
                    public function getRememberToken() {}
                    public function setRememberToken($value) {}
                    public function getRememberTokenName() {}
                }
            ),
            new Request(),
            $this->createTokenProvider()
        );

        try {
            $jwtGuard->login([
                $this->getFaker()->uuid => $this->getFaker()->uuid,
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]);

            $this->assertTrue(false);
        } catch (AuthorizationException $e) {
            $this->assertTrue(true);
        }

        $this->assertEmpty($jwtGuard->getJWT());
        $this->assertEmpty($jwtGuard->user());
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     * @throws Exception
     */
    public function testLoginWithInvalidCredentials(): void
    {
        $jwtGuard = $this->createJWTGuard(
            $this->createJWTHandler($this->createJWT()),
            $this->createUserProvider($this->createUser())->setValidCredentials(false),
            new Request(),
            $this->createTokenProvider()
        );

        try {
            $jwtGuard->login([
                $this->getFaker()->uuid => $this->getFaker()->uuid,
                $this->getFaker()->uuid => $this->getFaker()->uuid,
            ]);

            $this->assertTrue(false);
        } catch (AuthorizationException $e) {
            $this->assertTrue(true);
        }

        $this->assertEmpty($jwtGuard->getJWT());
        $this->assertEmpty($jwtGuard->user());
    }

    //endregion

    /**
     * @param JWTHandler|null    $jwtHandler
     * @param UserProvider|null  $userProvider
     * @param Request|null       $request
     * @param TokenProvider|null $tokenProvider
     *
     * @return JWTGuard
     *
     * @throws InvalidSecretException
     */
    private function createJWTGuard(
        JWTHandler $jwtHandler = null,
        UserProvider $userProvider = null,
        Request $request = null,
        TokenProvider $tokenProvider = null
    ): JWTGuard
    {
        return new JWTGuard(
            $jwtHandler ?: $this->createJWTHandler(),
            $userProvider ?: $this->createUserProvider(),
            $request ?: new Request(),
            $tokenProvider ?: $this->createTokenProvider()
        );
    }

    /**
     * @param JWT|null $jwt
     *
     * @return TestJWTHandler
     *
     * @throws InvalidSecretException
     */
    private function createJWTHandler(JWT $jwt = null): TestJWTHandler
    {
        return (new TestJWTHandler(
            $this->getFaker()->uuid,
            $this->getFaker()->uuid,
            $this->getFaker()->numberBetween()
        ))->setJWT($jwt);
    }

    /**
     * @param Authenticatable|null $user
     *
     * @return TestUserProvider
     */
    private function createUserProvider(Authenticatable $user = null): TestUserProvider
    {
        return (new TestUserProvider())->setUser($user);
    }

    /**
     * @param string|null $authIdentifierName
     * @param string|null $authIdentifier
     * @param string|null $authPassword
     *
     * @return JWTAuthenticatable
     */
    private function createUser(
        string $authIdentifierName = null,
        string $authIdentifier = null,
        string $authPassword = null
    ): JWTAuthenticatable
    {
        return new TestUser(
            $authIdentifierName ?? $this->getFaker()->uuid,
            $authIdentifier ?? $this->getFaker()->uuid,
            $authPassword ?? $this->getFaker()->password
        );
    }

    /**
     * @param string|null $token
     *
     * @return TokenProvider
     */
    private function createTokenProvider(string $token = null): TokenProvider
    {
        return (new TestTokenProvider())->setToken($token);
    }

    /**
     * @param Token|null $token
     *
     * @return JWT
     */
    private function createJWT(Token $token = null): JWT
    {
        return new JWT($token ?: $this->createToken());
    }
}
