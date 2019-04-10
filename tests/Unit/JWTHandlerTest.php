<?php

use Lcobucci\JWT\Builder;
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
    use ReflectionMethodHelper;

    //region Tests

    /**
     * @return void
     */
    public function testConstructInvalidSecretException(): void
    {
        try {
            new JWTHandler(
                '',
                $this->getFaker()->uuid,
                $this->createBuilder(),
                $this->createParser(),
                $this->createSigner()
            );

            $this->assertTrue(false);
        } catch (InvalidSecretException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @return void
     */
    public function testGetNewBuilder(): void
    {
        $builder = $this->createBuilder();
        $jwtHandler = new JWTHandler(
            $this->getFaker()->password,
            $this->getFaker()->uuid,
            $builder,
            $this->createParser(),
            $this->createSigner()
        );

        $newBuilder = $this->runGetNewBuilderMethod($jwtHandler);

        $this->assertEquals($builder, $newBuilder);
        $this->assertFalse($builder === $newBuilder);
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
        $secret = $this->getFaker()->password;
        $token = $this->createToken();
        $builder = $this->createBuilder($token);
        $signer = $this->createSigner();
        $expiryMinutes = $this->getFaker()->numberBetween();
        $issuer = $this->getFaker()->uuid;
        $subject = $this->getFaker()->uuid;
        $payloadItemName = $this->getFaker()->uuid;
        $payloadItemValue = $this->getFaker()->uuid;

        $jwtHandler = $this->createJWTHandler($secret, $issuer, $builder, null, $signer);
        $jwtHandler
            ->shouldReceive('getNewBuilder')
            ->andReturn($builder);

        $before = new \DateTimeImmutable();

        $this->assertEquals(
            new JWT($token),
            $jwtHandler->createJWT(
                $subject,
                [
                    $payloadItemName => $payloadItemValue,
                ],
                $expiryMinutes
            )
        );

        $after = new \DateTimeImmutable();

        $builder
            ->shouldHaveReceived('setIssuer')
            ->with($issuer)
            ->once();
        $builder
            ->shouldHaveReceived('setSubject')
            ->with($subject)
            ->once();
        $builder
            ->shouldHaveReceived('setIssuedAt')
            ->with(Mockery::on(function ($argument) use ($before, $after) {
                return ($argument >= $before->getTimestamp() && $argument <= $after->getTimestamp());
            }))
            ->once();
        $builder
            ->shouldHaveReceived('setExpiration')
            ->with(Mockery::on(function ($argument) use ($before, $after, $expiryMinutes) {
                return (
                    $argument >= $after->add(new \DateInterval('PT' . $expiryMinutes . 'M'))->getTimestamp()
                    && $argument <= $after->add(new \DateInterval('PT' . $expiryMinutes . 'M'))->getTimestamp()
                );
            }))
            ->once();
        $builder
            ->shouldHaveReceived('set')
            ->with(
                $payloadItemName,
                $payloadItemValue
            )
            ->once();
        $builder
            ->shouldHaveReceived('sign')
            ->with(
                Mockery::on(function ($argument) use ($signer) {
                    return $argument == $signer;
                }),
                $secret
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testCreateJWTWithEmptyPayload(): void
    {
        $token = $this->createToken();
        $builder = $this->createBuilder($token);

        $this->assertEquals(
            new JWT($token),
            $this->createJWTHandler(null, $this->getFaker()->uuid, $builder)->createJWT(
                 $this->getFaker()->uuid,
                 [],
                 $this->getFaker()->numberBetween()
             )
        );

        $builder->shouldNotHaveReceived('set');
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testCreateJWTWithoutTTL(): void
    {
        $token = $this->createToken();
        $builder = $this->createBuilder($token);

        $this->assertEquals(
            new JWT($token),
            $this->createJWTHandler(null, $this->getFaker()->uuid, $builder)->createJWT($this->getFaker()->uuid, [])
        );

        $builder->shouldNotHaveReceived('setExpiration');
    }

    /**
     * @return void
     *
     * @throws \Exception
     */
    public function testGetValidJWT(): void
    {
        $token = $this->createToken();
        $token
            ->shouldReceive('verify')
            ->andReturn(true)
            ->getMock()
            ->shouldReceive('isExpired')
            ->andReturn(false)
            ->getMock()
            ->shouldReceive('getClaim')
            ->andReturn((new \DateTimeImmutable())->sub(new \DateInterval('P1D'))->getTimestamp());
        $signer = $this->createSigner();
        $secret = $this->getFaker()->uuid;

        $this->assertEquals(
            new JWT($token),
            $this->createJWTHandler($secret, null, null, $this->createParser($token), $signer)
                 ->getValidJWT($this->getFaker()->uuid)
        );

        $token
            ->shouldHaveReceived('verify')
            ->with(
                Mockery::on(function ($argument) use ($signer) {
                    return $argument == $signer;
                }),
                $secret
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetValidJWTExpired(): void
    {
        $token = $this->createToken();
        $token
            ->shouldReceive('verify')
            ->andReturn(true)
            ->getMock()
            ->shouldReceive('isExpired')
            ->andReturn(true);

        $this->expectException(TokenExpiredException::class);

        $this->createJWTHandler(null, null, null, $this->createParser($token))
                    ->getValidJWT($this->getFaker()->uuid);
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testGetValidJWTBeforeValid(): void
    {
        $token = $this->createToken();
        $token
            ->shouldReceive('verify')
            ->andReturn(true)
            ->getMock()
            ->shouldReceive('isExpired')
            ->andReturn(false)
            ->getMock()
            ->shouldReceive('getClaim')
            ->andReturn((new \DateTimeImmutable())->add(new \DateInterval('P1D'))->getTimestamp());

        $this->expectException(BeforeValidException::class);

        $this->createJWTHandler(null, null, null, $this->createParser($token))
             ->getValidJWT($this->getFaker()->uuid);
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
        $token = $this->createToken();
        $token
            ->shouldReceive('verify')
            ->andReturn(false);

        $this->expectException(InvalidSignatureException::class);

        $this->createJWTHandler(null, null, null, $this->createParser($token))
             ->getValidJWT($this->getFaker()->uuid);
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
        $this->expectException(InvalidTokenException::class);

        $this->createJWTHandler(
            null,
            null,
            null,
            $this->createParser(new \InvalidArgumentException())
        )->getValidJWT($this->getFaker()->uuid);
    }

    //endregion

    /**
     * @param JWTHandler $jwtHandler
     * @param int|null   $minutes
     *
     * @return array
     *
     * @throws ReflectionException
     */
    private function runCreateTimestampsMethod(JWTHandler $jwtHandler, int $minutes = null): array
    {
        return $this->runReflectionMethod($jwtHandler, 'createTimestamps', [$minutes]);
    }

    /**
     * @param JWTHandler $jwtHandler
     *
     * @return Builder
     *
     * @throws \ReflectionException
     */
    private function runGetNewBuilderMethod(JWTHandler $jwtHandler): Builder
    {
        return $this->runReflectionMethod($jwtHandler, 'getNewBuilder');
    }
}
