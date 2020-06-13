<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Contracts\Auth\Factory;
use Illuminate\Contracts\Auth\Guard;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Middleware\AuthReturnMiddleware;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class AuthReturnMiddlewareTest
 *
 * @package SPie\LaravelJWT\Test\Unit
 */
final class AuthReturnMiddlewareTest extends TestCase
{
    use JWTHelper;
    use TestHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws NotAuthenticatedException
     */
    public function testHandle(): void
    {
        $request = new Request();
        $responseHeader = $this->getFaker()->uuid;
        $guardIdentifier = $this->getFaker()->uuid;
        $authFactory = $this->createAuthFactory($this->createGuard(false));

        $response = $this->createAuthReturnMiddleware($authFactory)->handle(
            $request,
            function (Request $handledRequest) use ($request, $responseHeader) {
                $response = new Response();
                $response->headers->set('Test', $responseHeader);

                return $response;
            },
            $guardIdentifier
        );

        $this->assertEquals($responseHeader, $response->headers->get('Test'));

        $authFactory
            ->shouldHaveReceived('guard')
            ->with($guardIdentifier)
            ->once();
    }

    /**
     * @return void
     *
     * @throws NotAuthenticatedException
     */
    public function testHandleWithError(): void
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->createAuthReturnMiddleware($this->createAuthFactory($this->createGuard(true)))
             ->handle(new Request(), function () {
             });
    }

    /**
     * @return void
     */
    public function testHandleWithoutJWTGuard(): void
    {
        $this->expectException(\TypeError::class);

        $this->createAuthReturnMiddleware($this->createAuthFactory(Mockery::spy(Guard::class)))
            ->handle(new Request(), function () {
            }, $this->getFaker()->uuid);
    }

    /**
     * @return void
     */
    public function testHandleWithAccessAndRefreshToken()
    {
        $accessToken = $this->getFaker()->uuid;
        $refreshToken = $this->getFaker()->uuid;
        $authFactory = $this->createAuthFactory($this->createGuard(
            false,
            $accessToken,
            $refreshToken
        ));

        $response = $this->createAuthReturnMiddleware($authFactory)->handle(
            new Request(),
            function (Request $handledRequest) {
                return new Response();
            },
            $this->getFaker()->uuid
        );

        $this->assertEquals($accessToken, $response->headers->get('Authorization'));
        $this->assertEquals($refreshToken, $response->headers->get('RefreshToken'));
    }

    /**
     * @return void
     */
    public function testHandleWithoutAccessToken()
    {
        $authFactory = $this->createAuthFactory($this->createGuard(
            false,
            new NotAuthenticatedException()
        ));

        $this->expectException(NotAuthenticatedException::class);

        $this->createAuthReturnMiddleware($authFactory)->handle(
            new Request(),
            function (Request $handledRequest) {
                return new Response();
            },
            $this->getFaker()->uuid
        );
    }

    /**
     * @return void
     */
    public function testHandleWithoutRefreshToken()
    {
        $accessToken = $this->getFaker()->uuid;
        $authFactory = $this->createAuthFactory($this->createGuard(
            false,
            $accessToken,
            new NotAuthenticatedException()
        ));

        $response = $this->createAuthReturnMiddleware($authFactory)->handle(
            new Request(),
            function (Request $handledRequest) {
                return new Response();
            },
            $this->getFaker()->uuid
        );

        $this->assertEquals($accessToken, $response->headers->get('Authorization'));
        $this->assertEmpty($response->headers->get('RefreshToken'));
    }

    //endregion

    //region Mocks

    /**
     * @param Factory $authFactory
     *
     * @return AuthReturnMiddleware
     */
    private function createAuthReturnMiddleware(Factory $authFactory): AuthReturnMiddleware
    {
        return new AuthReturnMiddleware($authFactory);
    }

    /**
     * @param Guard $jwtGuard
     *
     * @return Factory|MockInterface
     */
    private function createAuthFactory(Guard $jwtGuard): Factory
    {
        $authFactory = Mockery::spy(Factory::class);
        $authFactory
            ->shouldReceive('guard')
            ->andReturn($jwtGuard);

        return $authFactory;
    }

    /**
     * @param bool                   $isGuest
     * @param string|\Exception|null $accessToken
     * @param string|\Exception|null $refreshToken
     *
     * @return JWTGuard
     */
    private function createGuard(
        bool $isGuest = false,
        $accessToken = null,
        $refreshToken = null
    ): JWTGuard {
        $jwtGuard = $this->createJWTGuard();
        $this
            ->addGuest($jwtGuard, $isGuest)
            ->addReturnAccessToken($jwtGuard, $accessToken)
            ->addReturnRefreshToken($jwtGuard, $refreshToken);

        return $jwtGuard;
    }

    /**
     * @param Guard|MockInterface $jwtGuard
     * @param bool                $isGuest
     *
     * @return AuthReturnMiddlewareTest
     */
    private function addGuest(Guard $jwtGuard, bool $isGuest): AuthReturnMiddlewareTest
    {
        $jwtGuard
            ->shouldReceive('guest')
            ->andReturn($isGuest);

        return $this;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     * @param string|\Exception|null $accessToken
     *
     * @return AuthReturnMiddlewareTest
     */
    private function addReturnAccessToken(JWTGuard $jwtGuard, $accessToken = null): AuthReturnMiddlewareTest
    {
        $jwtGuard
            ->shouldReceive('returnAccessToken')
            ->andReturnUsing(function (Response $response) use ($accessToken) {
                if ($accessToken instanceof \Exception) {
                    throw $accessToken;
                }

                $response->headers->set('Authorization', $accessToken);

                return $response;
            });

        return $this;
    }

    /**
     * @param JWTGuard|MockInterface $jwtGuard
     * @param string|\Exception|null $refreshToken
     *
     * @return AuthReturnMiddlewareTest
     */
    private function addReturnRefreshToken(JWTGuard $jwtGuard, $refreshToken = null): AuthReturnMiddlewareTest
    {
        $jwtGuard
            ->shouldReceive('returnRefreshToken')
            ->andReturnUsing(function (Response $response) use ($refreshToken) {
                if ($refreshToken instanceof \Exception) {
                    throw $refreshToken;
                }

                $response->headers->set('RefreshToken', $refreshToken);

                return $response;
            });

        return $this;
    }

    //endregion
}
