<?php

namespace SPie\LaravelJWT\Test\Unit;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Mockery;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\Validator;
use SPie\LaravelJWT\Exceptions\BeforeValidException;
use SPie\LaravelJWT\Exceptions\TokenExpiredException;
use SPie\LaravelJWT\Exceptions\InvalidSecretException;
use SPie\LaravelJWT\Exceptions\InvalidTokenException;
use SPie\LaravelJWT\Exceptions\InvalidSignatureException;
use SPie\LaravelJWT\JWTHandler;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\ReflectionMethodHelper;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class JWTHandlerTest
 */
final class JWTHandlerTest extends TestCase
{
    use TestHelper;
    use JWTHelper;
    use ReflectionMethodHelper;

    //region Tests

    /**
     * @return void
     */
    public function testConstructInvalidSecretException(): void
    {
        $this->expectException(InvalidSecretException::class);

        new JWTHandler(
            '',
            $this->getFaker()->uuid,
            $this->createJWTFactory(),
            $this->createBuilder(),
            $this->createParser(),
            $this->createSigner(),
            $this->createValidator()
        );
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
            $this->createJWTFactory(),
            $builder,
            $this->createParser(),
            $this->createSigner(),
            $this->createValidator()
        );

        $newBuilder = $this->runGetNewBuilderMethod($jwtHandler);

        $this->assertEquals($builder, $newBuilder);
        $this->assertFalse($builder === $newBuilder);
    }

    /**
     * @return void
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
     */
    public function testCreateTimestampsWithoutTTL(): void
    {
        $this->assertEmpty($this->runCreateTimestampsMethod($this->createJWTHandler())[1]);
    }

    /**
     * @return void
     */
    public function testCreateJWT(): void
    {
        $jwt = $this->createJWT();
        $token = $this->createToken();
        $jwtFactory = $this->createJWTFactory($jwt);

        $jwtHandler = $this->createJWTHandler(null, null, $jwtFactory, $this->createBuilder($token));

        $this->assertEquals(
            $jwt,
            $jwtHandler->createJWT(
                $this->getFaker()->uuid,
                [
                    $this->getFaker()->uuid => $this->getFaker()->uuid,
                ],
                $this->getFaker()->numberBetween()
            )
        );

        $jwtFactory
            ->shouldHaveReceived('createJWT')
            ->with($token)
            ->once();
    }

    /**
     * @return void
     */
    public function testCreateJWTWithEmptyPayload(): void
    {
        $jwt = $this->createJWT();
        $token = $this->createToken();
        $jwtFactory = $this->createJWTFactory($jwt);
        $builder = $this->createBuilder($token);

        $this->assertEquals(
            $jwt,
            $this->createJWTHandler(null, $this->getFaker()->uuid, $jwtFactory, $builder)->createJWT(
                $this->getFaker()->uuid,
                [],
                $this->getFaker()->numberBetween()
            )
        );

        $builder->shouldNotHaveReceived('set');
    }

    /**
     * @return void
     */
    public function testCreateJWTWithoutTTL(): void
    {
        $jwt = $this->createJWT();
        $token = $this->createToken();
        $jwtFactory = $this->createJWTFactory($jwt);
        $builder = $this->createBuilder($token);

        $this->assertEquals(
            $jwt,
            $this->createJWTHandler(null, $this->getFaker()->uuid, $jwtFactory, $builder)
                 ->createJWT($this->getFaker()->uuid, [])
        );

        $builder->shouldNotHaveReceived('setExpiration');
    }

    /**
     * @return void
     */
    public function testGetValidJWT(): void
    {
        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getIssuedAt')
            ->andReturn((new \DateTimeImmutable())->sub(new \DateInterval('P1D')));
        $jwtFactory = $this->createJWTFactory($jwt);
        $token = $this->createToken();
        $token
            ->shouldReceive('isExpired')
            ->andReturn(false)
            ->getMock()
            ->shouldReceive('getClaim')
            ->andReturn((new \DateTimeImmutable())->sub(new \DateInterval('P1D'))->getTimestamp());
        $signer = $this->createSigner();
        $validator = $this->createValidator();
        $this->mockValidatorValidate($validator, true, $token);
        $secret = $this->getFaker()->uuid;

        $this->assertEquals(
            $jwt,
            $this->createJWTHandler($secret, null, $jwtFactory, null, $this->createParser($token), $signer, $validator)
                 ->getValidJWT($this->getFaker()->uuid)
        );
    }

    /**
     * @return void
     */
    public function testGetValidJWTExpired(): void
    {
        $token = $this->createToken();
        $token
            ->shouldReceive('isExpired')
            ->andReturn(true);
        $validator = $this->createValidator();
        $this->mockValidatorValidate($validator, true, $token);

        $this->expectException(TokenExpiredException::class);

        $this->createJWTHandler(null, null, null, null, $this->createParser($token), $this->createSigner(), $validator)
                    ->getValidJWT($this->getFaker()->uuid);
    }

    /**
     * @return void
     */
    public function testGetValidJWTBeforeValid(): void
    {
        $jwt = $this->createJWT();
        $jwt
            ->shouldReceive('getIssuedAt')
            ->andReturn((new \DateTimeImmutable())->add(new \DateInterval('P1D')));
        $jwtFactory = $this->createJWTFactory($jwt);
        $token = $this->createToken();
        $token
            ->shouldReceive('isExpired')
            ->andReturn(false)
            ->getMock()
            ->shouldReceive('getClaim')
            ->andReturn((new \DateTimeImmutable())->add(new \DateInterval('P1D'))->getTimestamp());
        $validator = $this->createValidator();
        $this->mockValidatorValidate($validator, true, $token);

        $this->expectException(BeforeValidException::class);

        $this->createJWTHandler(null, null, $jwtFactory, null, $this->createParser($token), $this->createSigner(), $validator)
             ->getValidJWT($this->getFaker()->uuid);
    }

    /**
     * @return void
     *
     * @throws BeforeValidException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws TokenExpiredException
     */
    public function testGetValidJWTSignatureInvalid(): void
    {
        $token = $this->createToken();
        $validator = $this->createValidator();
        $this->mockValidatorValidate($validator, false, $token);

        $this->expectException(InvalidSignatureException::class);

        $this->createJWTHandler(null, null, null, null, $this->createParser($token), $this->createSigner(), $validator)
             ->getValidJWT($this->getFaker()->uuid);
    }

    /**
     * @return void
     *
     * @throws BeforeValidException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws TokenExpiredException
     */
    public function testGetValidJWTInvalidTokenException(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->createJWTHandler(
            null,
            null,
            null,
            null,
            $this->createParser(new \InvalidArgumentException())
        )->getValidJWT($this->getFaker()->uuid);
    }

    //endregion

    /**
     * @param string|null     $secret
     * @param string|null     $issuer
     * @param JWTFactory|null $jwtFactory
     * @param Builder|null    $builder
     * @param Parser|null     $parser
     * @param Signer|null     $signer
     * @param Validator|null  $validator
     *
     * @return JWTHandler
     * @throws InvalidSecretException
     */
    private function createJWTHandler(
        string $secret = null,
        string $issuer = null,
        JWTFactory $jwtFactory = null,
        Builder $builder = null,
        Parser $parser = null,
        Signer $signer = null,
        Validator $validator = null
    ): JWTHandler {
        return new JWTHandler(
            $secret ?: $this->getFaker()->uuid,
            $issuer ?: $this->getFaker()->uuid,
            $jwtFactory ?: $this->createJWTFactory(),
            $builder ?: $this->createBuilder(),
            $parser ?: $this->createParser(),
            $signer ?: $this->getSigner(),
            $validator ?: $this->createValidator()
        );
    }

    /**
     * @param JWTHandler $jwtHandler
     * @param int|null   $minutes
     *
     * @return array
     */
    private function runCreateTimestampsMethod(JWTHandler $jwtHandler, int $minutes = null): array
    {
        return $this->runReflectionMethod($jwtHandler, 'createTimestamps', [$minutes]);
    }

    /**
     * @param JWTHandler $jwtHandler
     *
     * @return Builder
     */
    private function runGetNewBuilderMethod(JWTHandler $jwtHandler): Builder
    {
        return $this->runReflectionMethod($jwtHandler, 'getNewBuilder');
    }
}
