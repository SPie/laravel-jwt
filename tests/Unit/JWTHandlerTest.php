<?php

use SPie\LaravelJWT\Exceptions\BeforeValidException;
use SPie\LaravelJWT\Exceptions\TokenExpiredException;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\InvalidSignatureException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTHandler;

/**
 * Class JWTHandlerTest
 */
class JWTHandlerTest extends TestCase
{

    use JWTHelper;

    //region Tests

    /**
     * @return void
     */
    public function testConstructInvalidSecretException(): void
    {
        try {
            new JWTHandler('', $this->getFaker()->uuid, $this->getFaker()->numberBetween());

            $this->assertTrue(false);
        } catch (InvalidSecretException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testCreateTimestamps(): void
    {
        $minutes = $this->getFaker()->numberBetween();

        $jwtHandler = $this->createJWTHandler(null, null, $minutes);
        $createTimestampsMethod = (new \ReflectionObject($jwtHandler))->getMethod('createTimestamps');
        $createTimestampsMethod->setAccessible(true);

        $timestamps = $createTimestampsMethod->invoke($jwtHandler);

        $this->assertEquals(
            (new \DateTimeImmutable())->setTimestamp($timestamps[0])
                ->add(new \DateInterval('PT' . $minutes . 'M')),
            (new \DateTimeImmutable())->setTimestamp($timestamps[1])
        );
    }

    /**
     * @return void
     *
     * @throws InvalidSecretException
     */
    public function testCreateTimestampsWithoutTTL(): void
    {
        $jwtHandler = $this->createJWTHandler();
        $createTimestampsMethod = (new \ReflectionObject($jwtHandler))->getMethod('createTimestamps');
        $createTimestampsMethod->setAccessible(true);

        $timestamps = $createTimestampsMethod->invoke($jwtHandler);

        $this->assertEmpty($timestamps[1]);
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testCreateJWT(): void
    {
        $expiryMinutes = $this->getFaker()->numberBetween();
        $issuer = $this->getFaker()->uuid;
        $subject = $this->getFaker()->uuid;
        $payloadItemName = $this->getFaker()->uuid;
        $payloadItemValue = $this->getFaker()->uuid;

        $jwtHandler = $this->createJWTHandler(null, $issuer, $expiryMinutes);

        $jwt = $jwtHandler->createJWT(
            $subject,
            [
                $payloadItemName => $payloadItemValue,
            ]
        );

        $this->assertEquals($issuer, $jwt->getIssuer());
        $this->assertEquals($subject, $jwt->getSubject());
        $this->assertEquals($payloadItemValue, $jwt->getClaim($payloadItemName));
        $this->assertEquals(
            $jwt->getIssuedAt()->add(new \DateInterval('PT' . $expiryMinutes . 'M')),
            $jwt->getExpiresAt()
        );
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testCreateJWTWithoutTTL(): void
    {
        $issuer = $this->getFaker()->uuid;
        $subject = $this->getFaker()->uuid;
        $payloadItemName = $this->getFaker()->uuid;
        $payloadItemValue = $this->getFaker()->uuid;

        $jwtHandler = $this->createJWTHandler(null, $issuer);

        $jwt = $jwtHandler->createJWT(
            $subject,
            [
                $payloadItemName => $payloadItemValue,
            ]
        );

        $this->assertEquals($issuer, $jwt->getIssuer());
        $this->assertEquals($subject, $jwt->getSubject());
        $this->assertEquals($payloadItemValue, $jwt->getClaim($payloadItemName));
        $this->assertEmpty($jwt->getExpiresAt());
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetValidJWT(): void
    {
        $secret = $this->getFaker()->uuid;
        $issuer = $this->getFaker()->uuid;
        $payload = [
            JWT::CLAIM_ISSUER       => $issuer,
            JWT::CLAIM_SUBJECT      => $this->getFaker()->uuid,
            JWT::CLAIM_ISSUED_AT    => (new \DateTimeImmutable())->getTimestamp(),
            JWT::CLAIM_EXPIRES_AT   => (new \DateTimeImmutable('+1 hour'))->getTimestamp(),
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ];

        try {
            $jwt = $this->createJWTHandler($secret, $issuer)->getValidJWT($this->createToken($payload, $secret));

            $this->assertInstanceOf(JWT::class, $jwt);
            $this->assertEquals($payload, $jwt->getClaims());
        } catch (\Exception $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @void
     */
    public function testGetValidJWTWithEmptyPayload(): void
    {
        $secret = $this->getFaker()->uuid;

        try {
            $jwt = $this->createJWTHandler($secret, $this->getFaker()->uuid)
                        ->getValidJWT($this->createToken([], $secret));

            $this->assertInstanceOf(JWT::class, $jwt);
            $this->assertEquals([], $jwt->getClaims());
        } catch (\Exception $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetValidJWTExpired(): void
    {
        $secret = $this->getFaker()->uuid;
        $issuer = $this->getFaker()->uuid;
        $payload = [
            JWT::CLAIM_ISSUER       => $issuer,
            JWT::CLAIM_SUBJECT      => $this->getFaker()->uuid,
            JWT::CLAIM_ISSUED_AT    => (new \DateTimeImmutable())->getTimestamp(),
            JWT::CLAIM_EXPIRES_AT   => (new \DateTimeImmutable('-1 hour'))->getTimestamp(),
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ];

        try {
            $this->createJWTHandler($secret, $issuer)->getValidJWT($this->createToken($payload, $secret));
            $this->assertTrue(false);
        } catch (TokenExpiredException $e) {
            $this->assertTrue(true);
        } catch (\Exception $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetValidJWTBeforeValid(): void
    {
        $secret = $this->getFaker()->uuid;
        $issuer = $this->getFaker()->uuid;
        $payload = [
            JWT::CLAIM_ISSUER       => $issuer,
            JWT::CLAIM_SUBJECT      => $this->getFaker()->uuid,
            JWT::CLAIM_ISSUED_AT    => (new \DateTimeImmutable('+1 hour'))->getTimestamp(),
            JWT::CLAIM_EXPIRES_AT   => (new \DateTimeImmutable('+1 hour'))->getTimestamp(),
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ];
        $token = $this->createToken($payload, $secret);

        try {
            $this->createJWTHandler($secret, $issuer)->getValidJWT($token);
            $this->assertTrue(false);
        } catch (BeforeValidException $e) {
            $this->assertTrue(true);
        } catch (\Exception $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @return void
     */
    public function testGetValidJWTSignatureInvalid(): void
    {
        $secret = $this->getFaker()->uuid;

        try {
            $this->createJWTHandler($secret, $this->getFaker()->uuid)
                 ->getValidJWT($this->createToken([], $secret) . $this->getFaker()->uuid);
            $this->assertTrue(false);
        } catch (InvalidSignatureException $e) {
            $this->assertTrue(true);
        } catch (\Exception $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @return void
     */
    public function testGetValidJWTInvalidTokenException(): void
    {
        $secret = $this->getFaker()->uuid;

        try {
            $this->createJWTHandler($secret, $this->getFaker()->uuid)
                 ->getValidJWT(
                     \base64_encode($this->getFaker()->uuid) . '.' . \base64_encode($this->getFaker()->uuid)
                 );
            $this->assertTrue(false);
        } catch (InvalidTokenException $e) {
            $this->assertTrue(true);
        } catch (\Exception $e) {
            $this->assertTrue(false);
        }
    }

    //endregion

    /**
     * @param string|null $secret
     * @param string|null $issuer
     * @param int|null    $expiryMinutes
     *
     * @return JWTHandler
     *
     * @throws InvalidSecretException
     */
    private function createJWTHandler(
        string $secret = null,
        string $issuer = null,
        int $expiryMinutes = null
    ): JWTHandler
    {
        return new JWTHandler(
            $secret ?: $this->getFaker()->uuid,
            $issuer ?: $this->getFaker()->uuid,
            $expiryMinutes,
            $this->getSigner()
        );
    }
}
