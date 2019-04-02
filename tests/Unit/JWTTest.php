<?php

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Token;
use Mockery\MockInterface;
use SPie\LaravelJWT\Exceptions\MissingClaimException;
use SPie\LaravelJWT\JWT;

/**
 * Class JWTTest
 */
class JWTTest extends TestCase
{

    use JWTHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetToken(): void
    {
        $token = $this->createJWTToken();

        $this->assertEquals($token, $this->createJWT($token)->getToken());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetJWT(): void
    {
        $jwt = $this->getFaker()->uuid;
        $token = $this->createJWTToken();
        $this->addToString($token, $jwt);

        $this->assertEquals($jwt, $this->createJWT($token)->getJWT());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetIssuer(): void
    {
        $issuer = $this->getFaker()->uuid;
        $token = $this->createJWTToken($issuer);

        $this->assertEquals($issuer, $this->createJWT($token)->getIssuer());
        $token
            ->shouldHaveReceived('getClaim')
            ->with('iss')
            ->once();
    }

    /**
     * @return void
     *
     * @throws MissingClaimException
     */
    public function testGetIssuerEmpty(): void
    {
        $this->expectException(MissingClaimException::class);

        $this->createJWT($this->createJWTToken(new OutOfBoundsException()))->getIssuer();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetSubject(): void
    {
        $subject = $this->getFaker()->uuid;
        $token = $this->createJWTToken($subject);

        $this->assertEquals($subject, $this->createJWT($token)->getSubject());
        $token
            ->shouldHaveReceived('getClaim')
            ->with('sub')
            ->once();
    }

    /**
     * @return void
     *
     * @throws MissingClaimException
     */
    public function testGetSubjectEmpty(): void
    {
        $this->expectException(MissingClaimException::class);

        $this->createJWT($this->createJWTToken(new OutOfBoundsException()))->getSubject();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetIssuedAt(): void
    {
        $issuedAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));
        $token = $this->createJWTToken($issuedAt->getTimestamp());

        $this->assertEquals($issuedAt, $this->createJWT($token)->getIssuedAt());
        $token
            ->shouldHaveReceived('getClaim')
            ->with('iat')
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testGetIssuedAtEmpty(): void
    {
        $this->expectException(MissingClaimException::class);

        $this->createJWT($this->createJWTToken(new OutOfBoundsException()))->getIssuedAt();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetExpiresAt(): void
    {
        $expiresAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));
        $token = $this->createJWTToken($expiresAt->getTimestamp());

        $this->assertEquals($expiresAt, $this->createJWT($token)->getExpiresAt());
        $token
            ->shouldHaveReceived('getClaim')
            ->with('exp')
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetExpiresAtEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken(new OutOfBoundsException()))->getExpiresAt());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetClaims(): void
    {
        $claim = Mockery::mock(Claim::class);
        $claim
            ->shouldReceive('getValue')
            ->andReturn($this->getFaker()->uuid);

        $token = $this->createJWTToken(null, [$claim]);

        $this->assertEquals(
            [
                $claim->getValue()
            ],
            $this->createJWT($token)->getClaims()
        );
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetRefreshTokenId(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;
        $token = $this->createJWTToken($refreshTokenId);

        $this->assertEquals($refreshTokenId, $this->createJWT($token)->getRefreshTokenId());
        $token
            ->shouldHaveReceived('getClaim')
            ->with('rti')
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetRefreshTokenIdEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken())->getRefreshTokenId());
    }

    //endregion

    /**
     * @param Token $token
     *
     * @return JWT
     */
    private function createJWT(Token $token): JWT
    {
        return new JWT($token);
    }

    /**
     * @param mixed|null $claim
     * @param Claim[]    $claims
     *
     * @return Token|MockInterface
     */
    private function createJWTToken($claim = null, array $claims = []): Token
    {
        $token = Mockery::spy(Token::class);
        $token
            ->shouldReceive('getClaims')
            ->andReturn($claims);

        $getClaimExpectation = $token->shouldReceive('getClaim');
        if ($claim instanceof \Exception) {
            $getClaimExpectation->andThrow($claim);

            return $token;
        }

        $getClaimExpectation->andReturn($claim);

        return $token;
    }

    /**
     * @param Token|MockInterface $token
     * @param string|null         $jwt
     *
     * @return JWTTest
     */
    private function addToString(Token $token, string $jwt = null): JWTTest
    {
        $token
            ->shouldReceive('__toString')
            ->andReturn($jwt);

        return $this;
    }
}
