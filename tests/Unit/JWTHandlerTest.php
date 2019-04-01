<?php

use Mockery\MockInterface;
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
            new JWTHandler('', $this->getFaker()->uuid);

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

        $timestamps = $this->runCreateTimestampsMethod($this->createJWTHandler(), $minutes);

        $this->assertEquals(
            (new \DateTimeImmutable())->setTimestamp($timestamps[0])
                ->add(new \DateInterval('PT' . $minutes . 'M')),
            (new \DateTimeImmutable())->setTimestamp($timestamps[1])
        );
    }

    /**
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testCreateTimestampsWithoutTTL(): void
    {
        $this->assertEmpty($this->runCreateTimestampsMethod($this->createJWTHandler())[1]);
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

        $jwt = $this->createJWTHandler(null, $issuer)->createJWT(
            $subject,
            [
                $payloadItemName => $payloadItemValue,
            ],
            $expiryMinutes
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

        $jwt = $this->createJWTHandler(null, $issuer)->createJWT(
            $subject,
            [
                $payloadItemName => $payloadItemValue,
            ]
        );

        $this->assertEquals($issuer, $jwt->getIssuer());
        $this->assertEquals($subject, $jwt->getSubject());
        $this->assertEquals($payloadItemValue, $jwt->getClaim($payloadItemName));
        $this->assertEmpty($jwt->getExpiresAt());
        $this->assertArrayNotHasKey('exp', $jwt->getToken()->getClaims());
    }

    /**
     * @return void
     *
     * @throws \Exception
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

        $jwt = $this->createJWTHandler($secret, $issuer)->getValidJWT($this->createToken($payload, $secret));

        $this->assertInstanceOf(JWT::class, $jwt);
        $this->assertEquals($payload, $jwt->getClaims());
    }

    /**
     * @return void
     *
     * @throws BeforeValidException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws TokenExpiredException
     * @throws \Exception
     */
    public function testGetValidJWTWithEmptyPayload(): void
    {
        $secret = $this->getFaker()->uuid;

        $jwt = $this->createJWTHandler($secret, $this->getFaker()->uuid)
                    ->getValidJWT($this->createToken([], $secret));

        $this->assertInstanceOf(JWT::class, $jwt);
        $this->assertEquals([], $jwt->getClaims());
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

        $this->expectException(TokenExpiredException::class);

        $this->createJWTHandler($secret, $issuer)->getValidJWT($this->createToken($payload, $secret));
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

        $this->expectException(BeforeValidException::class);

        $this->createJWTHandler($secret, $issuer)->getValidJWT($token);
    }

    /**
     * @return void
     *
     * @throws BeforeValidException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws TokenExpiredException
     * @throws \Exception
     */
    public function testGetValidJWTSignatureInvalid(): void
    {
        $secret = $this->getFaker()->uuid;

        $this->expectException(InvalidSignatureException::class);

        $this->createJWTHandler($secret, $this->getFaker()->uuid)
             ->getValidJWT($this->createToken([], $secret) . $this->getFaker()->uuid);
    }

    /**
     * @return void
     *
     * @throws BeforeValidException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws TokenExpiredException
     * @throws \Exception
     */
    public function testGetValidJWTInvalidTokenException(): void
    {
        $secret = $this->getFaker()->uuid;

        $this->expectException(InvalidTokenException::class);

        $this->createJWTHandler($secret, $this->getFaker()->uuid)
             ->getValidJWT(
                 \base64_encode($this->getFaker()->uuid) . '.' . \base64_encode($this->getFaker()->uuid)
             );
    }

    //endregion

    /**
     * @param string|null $secret
     * @param string|null $issuer
     *
     * @return JWTHandler|MockInterface
     */
    private function createJWTHandler(string $secret = null, string $issuer = null): JWTHandler
    {
        $jwtHandler = Mockery::spy(
            JWTHandler::class, [
                $secret ?: $this->getFaker()->uuid,
                $issuer ?: $this->getFaker()->uuid,
                $this->getSigner()
            ]
        );

        return $jwtHandler
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
    }

    /**
     * @param JWTHandler $jwtHandler
     * @param int|null   $minutes
     *
     * @return mixed
     * @throws ReflectionException
     */
    private function runCreateTimestampsMethod(JWTHandler $jwtHandler, int $minutes = null)
    {
        $reflectionObject = new \ReflectionObject($jwtHandler);
        $reflectionMethod = $reflectionObject->getMethod('createTimestamps');
        $reflectionMethod->setAccessible(true);

        return $reflectionMethod->invokeArgs($jwtHandler, [$minutes]);
    }
}
