<?php

namespace SPie\LaravelJWT\Test\Unit;

use Carbon\CarbonImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Mockery;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTFactory;
use SPie\LaravelJWT\Contracts\Validator;
use SPie\LaravelJWT\Exceptions\BeforeValidException;
use SPie\LaravelJWT\Exceptions\TokenExpiredException;
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

    protected function tearDown(): void
    {
        parent::tearDown();

        CarbonImmutable::setTestNow();
    }

    //region Tests

    /**
     * @return void
     */
    public function testCreateTimestamps(): void
    {
        $minutes = $this->getFaker()->numberBetween();

        $timestamps = $this->runCreateTimestampsMethod($this->createJWTHandler(), $minutes);

        $this->assertEquals(
            $timestamps[0]->add(new \DateInterval('PT' . $minutes . 'M')),
            $timestamps[1]
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
     * @return array
     */
    private function setUpCreateJWTTest(): array
    {

        $jwt = $this->createJWT();
        $token = $this->createPlainToken();
        $jwtFactory = $this->createJWTFactory();
        $this->mockJWTFactoryCreateJWT($jwtFactory, $jwt, $token);
        $signer = $this->createSigner();
        $key = $this->createKey();
        $builder = $this->createBuilder();
        $this->mockBuilderGetToken($builder, $token, $signer, $key);
        $configuration = $this->createConfiguration($signer, $key);
        $configuration->setBuilderFactory($this->createBuilderFactory($builder));

        $jwtHandler = $this->createJWTHandler(
            null,
            $jwtFactory,
            null,
            $configuration
        );

        return [$jwtHandler, $jwt, $builder];
    }

    /**
     * @return void
     */
    public function testCreateJWT(): void
    {
        [$jwtHandler, $jwt] = $this->setUpCreateJWTTest();

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
    }

    /**
     * @return void
     */
    public function testCreateJWTWithEmptyPayload(): void
    {
        [$jwtHandler, $jwt, $builder] = $this->setUpCreateJWTTest();

        $this->assertEquals(
            $jwt,
            $jwtHandler->createJWT(
                $this->getFaker()->uuid,
                [],
                $this->getFaker()->numberBetween()
            )
        );
        $builder->shouldNotHaveReceived('withClaim');
    }

    /**
     * @return void
     */
    public function testCreateJWTWithoutTTL(): void
    {
        [$jwtHandler, $jwt, $builder] = $this->setUpCreateJWTTest();

        $this->assertEquals(
            $jwt,
            $jwtHandler->createJWT(
                $this->getFaker()->uuid,
                [
                    $this->getFaker()->uuid => $this->getFaker()->uuid,
                ]
            )
        );
        $builder->shouldNotHaveReceived('expiresAt');
    }

    /**
     * @return array
     */
    private function setUpGetValidJWTTest(
        bool $expired = false,
        bool $issuedBefore = true,
        bool $validToken = true,
        bool $validParsedToken = true
    ): array {
        $input = $this->getFaker()->sha256;
        $now = new CarbonImmutable();
        CarbonImmutable::setTestNow($now);
        $jwt = $this->createJWT();
        $token = $this->createToken();
        $token
            ->shouldReceive('isExpired')
            ->with(Mockery::on(fn (\DateTimeImmutable $actual) => $now == $actual))
            ->andReturn($expired)
            ->getMock()
            ->shouldReceive('hasBeenIssuedBefore')
            ->with(Mockery::on(fn (\DateTimeImmutable $actual) => $now == $actual))
            ->andReturn($issuedBefore)
            ->getMock();
        $jwtFactory = $this->createJWTFactory();
        $this->mockJWTFactoryCreateJWT($jwtFactory, $jwt, $token);
        $validator = $this->createValidator();
        $this->mockValidatorValidate($validator, $validToken, $token);
        $parser = $this->createParser();
        $this->mockParserParse($parser, $validParsedToken ? $token : new \InvalidArgumentException(), $input);
        $jwtHandler = $this->createJWTHandler(null, $jwtFactory, $validator, null, $parser);

        return [$jwtHandler, $input, $jwt];
    }

    /**
     * @return void
     */
    public function testGetValidJWT(): void
    {
        [$jwtHandler, $input, $jwt] = $this->setUpGetValidJWTTest();

        $this->assertEquals($jwt, $jwtHandler->getValidJWT($input));
    }

    /**
     * @return void
     */
    public function testGetValidJWTExpired(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(true);

        $this->expectException(TokenExpiredException::class);

        $jwtHandler->getValidJWT($input);
    }

    /**
     * @return void
     */
    public function testGetValidJWTBeforeValid(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(false, false);

        $this->expectException(BeforeValidException::class);

        $jwtHandler->getValidJWT($input);
    }

    /**
     * @return void
     */
    public function testGetValidJWTSignatureInvalid(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(false, true, false);

        $this->expectException(InvalidSignatureException::class);

        $jwtHandler->getValidJWT($input);
    }

    /**
     * @return void
     */
    public function testGetValidJWTInvalidTokenException(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(false, true, true, false);

        $this->expectException(InvalidTokenException::class);

        $jwtHandler->getValidJWT($input);
    }

    //endregion

    /**
     * @param string|null        $issuer
     * @param JWTFactory|null    $jwtFactory
     * @param Validator|null     $validator
     * @param Configuration|null $configuration
     * @param Parser|null        $parser
     *
     * @return JWTHandler
     */
    private function createJWTHandler(
        string $issuer = null,
        JWTFactory $jwtFactory = null,
        Validator $validator = null,
        Configuration $configuration = null,
        Parser $parser = null
    ): JWTHandler {
        return new JWTHandler(
            $issuer ?: $this->getFaker()->uuid,
            $jwtFactory ?: $this->createJWTFactory(),
            $validator ?: $this->createValidator(),
            $configuration ?: $this->createConfiguration(),
            $parser ?: $this->createParser()
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
     * @param Builder|null $builder
     *
     * @return \Closure
     */
    private function createBuilderFactory(Builder $builder = null): \Closure
    {
        return fn (ClaimsFormatter $claimsFormatter) => $builder ?: $this->createBuilder();
    }
}
