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

final class JWTTest extends TestCase
{
    use TestHelper;
    use JWTHelper;

    private function createJWT(Token $token): JWT
    {
        return new JWT($token);
    }

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

    //region Tests

    public function testGetJWT(): void
    {
        $jwt = $this->getFaker()->sha256;
        $token = $this->createJWTToken();
        $token
            ->shouldReceive('toString')
            ->andReturn($jwt);

        $this->assertEquals($jwt, $this->createJWT($token)->getJWT());
    }

    public function testGetIssuer(): void
    {
        $issuer = $this->getFaker()->uuid;

        $this->assertEquals($issuer, $this->createJWT($this->createJWTToken(null, ['iss' => $issuer]))->getIssuer());
    }

    public function testGetIssuerEmpty(): void
    {
        $this->assertNull($this->createJWT($this->createJWTToken())->getIssuer());
    }

    public function testGetSubject(): void
    {
        $subject = $this->getFaker()->uuid;

        $this->assertEquals($subject, $this->createJWT($this->createJWTToken(null, ['sub' => $subject]))->getSubject());
    }

    public function testGetSubjectEmpty(): void
    {
        $this->assertNull($this->createJWT($this->createJWTToken())->getSubject());
    }

    public function testGetIssuedAt(): void
    {
        $issuedAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));

        $this->assertEquals($issuedAt, $this->createJWT($this->createJWTToken(null, ['iat' => $issuedAt]))->getIssuedAt());
    }

    public function testGetIssuedAtEmpty(): void
    {
        $this->assertNull($this->createJWT($this->createJWTToken())->getIssuedAt());
    }

    public function testGetExpiresAt(): void
    {
        $expiresAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));

        $this->assertEquals($expiresAt, $this->createJWT($this->createJWTToken(null, ['exp' => $expiresAt]))->getExpiresAt());
    }

    public function testGetExpiresAtEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken(new OutOfBoundsException()))->getExpiresAt());
    }

    public function testGetClaims(): void
    {
        $claims = [$this->getFaker()->word => $this->getFaker()->word];
        $token = $this->createJWTToken(null, $claims);

        $this->assertEquals($claims, $this->createJWT($token)->getClaims());
    }

    public function testGetRefreshTokenId(): void
    {
        $refreshTokenId = $this->getFaker()->uuid;

        $this->assertEquals($refreshTokenId, $this->createJWT($this->createJWTToken(null, ['rti' => $refreshTokenId]))->getRefreshTokenId());
    }

    public function testGetRefreshTokenIdEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken())->getRefreshTokenId());
    }

    public function testGetIpAddress(): void
    {
        $ipAddress = $this->getFaker()->ipv4;

        $this->assertEquals($ipAddress, $this->createJWT($this->createJWTToken(null, ['ipa' => $ipAddress]))->getIpAddress());
    }

    public function testGetIpAddressWithoutIpAddress(): void
    {
        $this->assertEmpty($this->createJWT($this->createJWTToken())->getIpAddress());
    }

    //endregion
}
