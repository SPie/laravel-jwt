<?php

use Lcobucci\JWT\Token;
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
     */
    public function testGetToken(): void
    {
        $token = $this->createToken();

        $this->assertEquals($token, $this->createJWT($token)->getToken());
    }

    /**
     * @return void
     */
    public function testGetJWT(): void
    {
        $token = $this->createToken();

        $this->assertEquals((string)$token, $this->createJWT($token)->getJWT());
    }

    /**
     * @return void
     */
    public function testGetIssuer(): void
    {
        $issuer = $this->getFaker()->uuid;

        $this->assertEquals($issuer, $this->createJWT($this->createToken([JWT::CLAIM_ISSUER => $issuer]))->getIssuer());
    }

    /**
     * @return void
     */
    public function testGetIssuerEmpty(): void
    {
        try {
            $this->createJWT($this->createToken())->getIssuer();

            $this->assertTrue(false);
        } catch (\Throwable $t) {
            $this->assertTrue(true);
        }
    }

    /**
     * @return void
     */
    public function testGetSubject(): void
    {
        $subject = $this->getFaker()->uuid;

        $this->assertEquals(
            $subject,
            $this->createJWT($this->createToken([JWT::CLAIM_SUBJECT => $subject]))->getSubject()
        );
    }

    /**
     * @return void
     */
    public function testGetSubjectEmpty(): void
    {
        try {
            $this->createJWT($this->createToken())->getSubject();

            $this->assertTrue(false);
        } catch (\Throwable $t) {
            $this->assertTrue(true);
        }
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetIssuedAt(): void
    {
        $issuedAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));

        $this->assertEquals(
            $issuedAt,
            $this->createJWT($this->createToken([JWT::CLAIM_ISSUED_AT => $issuedAt->getTimestamp()]))->getIssuedAt()
        );
    }

    /**
     * @return void
     */
    public function testGetIssuedAtEmpty(): void
    {
        try {
            $this->createJWT($this->createToken())->getIssuedAt();

            $this->assertTrue(false);
        } catch (\Throwable $t) {
            $this->assertTrue(true);
        }
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetExpiresAt(): void
    {
        $expiresAt = new \DateTimeImmutable($this->getFaker()->dateTime()->format('Y-m-d H:i:s'));

        $this->assertEquals(
            $expiresAt,
            $this->createJWT($this->createToken([JWT::CLAIM_EXPIRES_AT => $expiresAt->getTimestamp()]))->getExpiresAt()
        );
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetExpiresAtEmpty(): void
    {
        $this->assertEmpty($this->createJWT($this->createToken())->getExpiresAt());
    }

    /**
     * @return void
     */
    public function testGetClaims(): void
    {
        $payload = [
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ];

        $this->assertEquals($payload, $this->createJWT($this->createToken($payload))->getClaims());
    }

    //endregion

    /**
     * @param Token $token
     *
     * @return JWT
     */
    public function createJWT(Token $token): JWT
    {
        return new JWT($token);
    }
}
