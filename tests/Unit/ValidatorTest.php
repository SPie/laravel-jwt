<?php

namespace SPie\LaravelJWT\Test\Unit;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validator as LcobucciValidator;
use Lcobucci\JWT\Validation\Constraint;
use Mockery as m;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Validator;

final class ValidatorTest extends TestCase
{
    use JWTHelper;

    private function getValidator(?LcobucciValidator $validator = null, ?Constraint $constraint = null): Validator
    {
        return new Validator(
            $validator ?: $this->createLcobucciValidator(),
            $constraint ?: $this->createConstraint()
        );
    }

    /**
     * @return LcobucciValidator|MockInterface
     */
    private function createLcobucciValidator(): LcobucciValidator
    {
        return m::spy(LcobucciValidator::class);
    }

    private function mockLcobucciValidatorValidate(
        MockInterface $validator,
        bool $valid,
        Token $token,
        Constraint $constraint
    ): self {
        $validator
            ->shouldReceive('validate')
            ->with($token, $constraint)
            ->andReturn($valid);

        return $this;
    }

    /**
     * @return Constraint|MockInterface
     */
    private function createConstraint(): Constraint
    {
        return m::spy(Constraint::class);
    }

    public function testValidateWithValidToken(): void
    {
        $token = $this->createToken();
        $constraint = $this->createConstraint();
        $lcobucciValidator = $this->createLcobucciValidator();
        $this->mockLcobucciValidatorValidate($lcobucciValidator, true, $token, $constraint);

        $this->assertTrue($this->getValidator($lcobucciValidator, $constraint)->validate($token));
    }

    public function testValidateWithoutValidToken(): void
    {
        $token = $this->createToken();
        $constraint = $this->createConstraint();
        $lcobucciValidator = $this->createLcobucciValidator();
        $this->mockLcobucciValidatorValidate($lcobucciValidator, false, $token, $constraint);

        $this->assertFalse($this->getValidator($lcobucciValidator, $constraint)->validate($token));
    }
}
