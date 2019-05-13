<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Contracts\Auth\Factory;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Middleware\AuthMiddleware;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class AuthMiddlewareTest
 */
final class AuthMiddlewareTest extends TestCase
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
        $response = $this->getFaker()->uuid;
        $guardIdentifier = $this->getFaker()->uuid;
        $jwtGuard = $this->createJWTGuard();
        $this->addGuest($jwtGuard, false);
        $authFactory = $this->createAuthFactory($jwtGuard);

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
        $jwtGuard = $this->createJWTGuard();
        $this->addGuest($jwtGuard, true);

        $this->expectException(NotAuthenticatedException::class);

        $this->createAuthMiddleware($this->createAuthFactory($jwtGuard))
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
     * @param JWTGuard|MockInterface $jwtGuard
     * @param bool                   $isGuest
     *
     * @return AuthMiddlewareTest
     */
    private function addGuest(JWTGuard $jwtGuard, bool $isGuest): AuthMiddlewareTest
    {
        $jwtGuard
            ->shouldReceive('guest')
            ->andReturn($isGuest);

        return $this;
    }

    //endregion
}
