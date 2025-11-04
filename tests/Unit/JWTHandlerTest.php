<?php

namespace SPie\LaravelJWT\Test\Unit;

use Carbon\CarbonImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
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

    private function createJWTHandler(
        ?string $issuer = null,
        ?JWTFactory $jwtFactory = null,
        ?Validator $validator = null,
        ?Signer $signer = null,
        ?Key $signingKey = null,
        ?Parser $parser = null,
        ?Builder $builder = null
    ): JWTHandler {
        return new JWTHandler(
            $issuer ?: $this->getFaker()->uuid,
            $jwtFactory ?: $this->createJWTFactory(),
            $validator ?: $this->createValidator(),
            $signer ?: $this->createSigner(),
            $signingKey ?: $this->createKey(),
            $parser ?: $this->createParser(),
            $builder ?: $this->createBuilder()
        );
    }

    private function runCreateTimestampsMethod(JWTHandler $jwtHandler, ?int $minutes = null): array
    {
        return $this->runReflectionMethod($jwtHandler, 'createTimestamps', [$minutes]);
    }

    private function createBuilderFactory(?Builder $builder = null): \Closure
    {
        return fn (ClaimsFormatter $claimsFormatter) => $builder ?: $this->createBuilder();
    }

    //region Tests

    public function testCreateTimestamps(): void
    {
        $minutes = $this->getFaker()->numberBetween();

        $timestamps = $this->runCreateTimestampsMethod($this->createJWTHandler(), $minutes);

        $this->assertEquals(
            $timestamps[0]->add(new \DateInterval('PT' . $minutes . 'M')),
            $timestamps[1]
        );
    }

    public function testCreateTimestampsWithoutTTL(): void
    {
        $this->assertEmpty($this->runCreateTimestampsMethod($this->createJWTHandler())[1]);
    }

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

        $jwtHandler = $this->createJWTHandler(
            null,
            $jwtFactory,
            null,
            $signer,
            $key,
            null,
            $builder
        );

        return [$jwtHandler, $jwt, $builder];
    }

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
        $jwtHandler = $this->createJWTHandler(
            null,
            $jwtFactory,
            $validator,
            null,
            null,
            $parser
        );

        return [$jwtHandler, $input, $jwt];
    }

    public function testGetValidJWT(): void
    {
        [$jwtHandler, $input, $jwt] = $this->setUpGetValidJWTTest();

        $this->assertEquals($jwt, $jwtHandler->getValidJWT($input));
    }

    public function testGetValidJWTExpired(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(true);

        $this->expectException(TokenExpiredException::class);

        $jwtHandler->getValidJWT($input);
    }

    public function testGetValidJWTBeforeValid(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(false, false);

        $this->expectException(BeforeValidException::class);

        $jwtHandler->getValidJWT($input);
    }

    public function testGetValidJWTSignatureInvalid(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(false, true, false);

        $this->expectException(InvalidSignatureException::class);

        $jwtHandler->getValidJWT($input);
    }

    public function testGetValidJWTInvalidTokenException(): void
    {
        [$jwtHandler, $input] = $this->setUpGetValidJWTTest(false, true, true, false);

        $this->expectException(InvalidTokenException::class);

        $jwtHandler->getValidJWT($input);
    }
}
