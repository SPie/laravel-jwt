<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Auth\AuthenticationException;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Middleware\JWTAuthentication;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\RequestHelper;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class JWTAuthenticationTest
 *
 * @package SPie\LaravelJWT\Test\Unit
 */
final class JWTAuthenticationTest extends TestCase
{
    use HttpHelper;
    use JWTHelper;
    use RequestHelper;

    //region Tests

    /**
     * @param bool $withAuthenticatedUser
     *
     * @return array
     */
    private function setUpHandleTest(bool $withAuthenticatedUser = true): array
    {
        $request = $this->createRequest();
        $response = $this->createEmptyResponse();
        $next = fn (Request $request) => $response;
        $jwtGuard = $this->createJWTGuard();
        $this
            ->mockJWTGuardGuest($jwtGuard, !$withAuthenticatedUser)
            ->mockJWTGuardReturnTokens($jwtGuard, $response);
        $jwtAuthentication = $this->getJWTAuthentication($jwtGuard);
    
        return [$jwtAuthentication, $request, $next, $response, $jwtGuard];
    }

    /**
     * @return void
     */
    public function testHandle(): void
    {
        /**
         * @var JWTAuthentication $jwtAuthentication
         * @var JWTGuard $jwtGuard
         */
        [$jwtAuthentication, $request, $next, $response, $jwtGuard] = $this->setUpHandleTest();

        $this->assertEquals($response, $jwtAuthentication->handle($request, $next));
        $this->assertJWTGuardReturnTokens($jwtGuard, $response);
    }

    /**
     * @return void
     */
    public function testHandleWithoutAuthenticatedUser(): void
    {
        /** @var JWTAuthentication $jwtAuthentication */
        [$jwtAuthentication, $request, $next] = $this->setUpHandleTest(false);

        $this->expectException(AuthenticationException::class);

        $jwtAuthentication->handle($request, $next);
    }

    //endregion

    /**
     * @param JWTGuard|null $jwtGuard
     *
     * @return JWTAuthentication
     */
    private function getJWTAuthentication(JWTGuard $jwtGuard = null): JWTAuthentication
    {
        return new JWTAuthentication($jwtGuard ?: $this->createJWTGuard());
    }
}
