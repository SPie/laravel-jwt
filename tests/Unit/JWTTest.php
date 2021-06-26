<?php

namespace SPie\LaravelJWT\Test\Unit;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\UnencryptedToken;
use Mockery;
use Mockery\MockInterface;
use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Exceptions\MissingClaimException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class JWTTest
 */
final class JWTTest extends TestCase
{
    use TestHelper;
    use JWTHelper;

    //region Tests

    /**
     * @return void
     */
    public function testGetJWT(): void
    {
        $jwt = $this->getFaker()->sha256;
        $token = $this->createJWTToken();
        $token
            ->shouldReceive('toString')
            ->andReturn($jwt);

        $this->assertEquals($jwt, $this->createJWT($token)->getJWT());
    }

    /**
     * @return void
     */
    public function testGetIssuer(): void
    {
        $issuer = $this->getFaker()->uuid;

        $this->assertEquals($issuer, $this->createJWT($this->createJWTToken(null, ['iss' => $issuer]))->getIssuer());
    }

    /**
     * @return void
     *
     * @throws MissingClaimException
     */
    public function testGetIssuerEmpty(): void
    {
        $this->assertNull($this->createJWT($this->createJWTToken())->getIssuer());
    }

    /**
     * @return void
     */
    public function testGetSubject(): void
    {
        $subject = $this->getFaker()->uuid;

        $this->assertEquals($subject, $this->createJWT($this->createJWTToken(null, ['sub' => $subject]))->getSubject());
    }

    /**
     * @return void
     */
    public function testGetSubjectEmpty(): void
    {
        $this->assertNull($this->createJWT($this->createJWTToken())->getSubject());
    }

    /**
     * @return void
     */
    public function testGetIssuedAt(): void
    {
        $issuedAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));

        $this->assertEquals($issuedAt, $this->createJWT($this->createJWTToken(null, ['iat' => $issuedAt->getTimestamp()]))->getIssuedAt());
    }

    /**
     * @return void
     */
    public function testGetIssuedAtEmpty(): void
    {
        $this->assertNull($this->createJWT($this->createJWTToken())->getIssuedAt());
    }

    /**
     * @return void
     */
    public function testGetExpiresAt(): void
    {
        $expiresAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));

        $this->assertEquals($expiresAt, $this->createJWT($this->createJWTToken(null, ['exp' => $expiresAt->getTimestamp()]))->getExpiresAt());
    }

    /**
     * @return void
     */
    public function testGetExpiresAtEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken(new OutOfBoundsException()))->getExpiresAt());
    }

    /**
     * @return void
     */
    public function testGetClaims(): void
    {
        $claims = [$this->getFaker()->word => $this->getFaker()->word];
        $token = $this->createJWTToken(null, $claims);

        $this->assertEquals($claims, $this->createJWT($token)->getClaims());
    }

    /**
     * @return void
     */
    public function testGetRefreshTokenId(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;

        $this->assertEquals($refreshTokenId, $this->createJWT($this->createJWTToken(null, ['rti' => $refreshTokenId]))->getRefreshTokenId());
    }

    /**
     * @return void
     */
    public function testGetRefreshTokenIdEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken())->getRefreshTokenId());
    }

    /**
     * @return void
     */
    public function testGetIpAddress(): void
    {
        $ipAddress = $this->getFaker()->ipv4;

        $this->assertEquals($ipAddress, $this->createJWT($this->createJWTToken(null, ['ipa' => $ipAddress]))->getIpAddress());
    }

    /**
     * @return void
     */
    public function testGetIpAddressWithoutIpAddress(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken())->getIpAddress());
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
     * @param array      $claims
     *
     * @return Token|MockInterface
     */
    private function createJWTToken($claim = null, array $claims = []): Token
    {
        $dataSet = new DataSet($claims, $this->getFaker()->sha256);
        $token = Mockery::spy(UnencryptedToken::class);
        $token
            ->shouldReceive('claims')
            ->andReturn($dataSet);

        $getClaimExpectation = $token->shouldReceive('getClaim');
        if ($claim instanceof \Exception) {
            $getClaimExpectation->andThrow($claim);

            return $token;
        }

        $getClaimExpectation->andReturn($claim);

        return $token;
    }
}
