<?php

use Illuminate\Contracts\Auth\Factory;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Auth\JWTGuard;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Middleware\AuthMiddleware;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class AuthMiddlewareTest
 */
final class AuthMiddlewareTest extends TestCase
{

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
        $response = $this->getFaker()->uuid;
        $guardIdentifier = $this->getFaker()->uuid;
        $authFactory = $this->createAuthFactory($this->createJWTGuard(false));

        $this->assertEquals(
            $response,
            $this->createAuthMiddleware($authFactory)->handle(
                $request,
                function (Request $handledRequest) use ($request, $response) {
                    if ($handledRequest !== $request) {
                        return null;
                    }

                    return $response;
                },
                $guardIdentifier
            )
        );

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

        $this->createAuthMiddleware($this->createAuthFactory($this->createJWTGuard(true)))
             ->handle(new Request(), function () {});
    }

    //endregion

    //region Mocks

    /**
     * @param Factory $authFactory
     *
     * @return AuthMiddleware
     */
    private function createAuthMiddleware(Factory $authFactory): AuthMiddleware
    {
        return new AuthMiddleware($authFactory);
    }

    /**
     * @param JWTGuard $jwtGuard
     *
     * @return Factory|MockInterface
     */
    private function createAuthFactory(JWTGuard $jwtGuard): Factory
    {
        $authFactory = Mockery::spy(Factory::class);
        $authFactory
            ->shouldReceive('guard')
            ->andReturn($jwtGuard);

        return $authFactory;
    }

    /**
     * @param bool $isGuest
     *
     * @return JWTGuard|MockInterface
     */
    private function createJWTGuard(bool $isGuest): JWTGuard
    {
        $jwtGuard = Mockery::spy(JWTGuard::class);
        $jwtGuard
            ->shouldReceive('guest')
            ->andReturn($isGuest);

        return $jwtGuard;
    }

    //endregion
}
