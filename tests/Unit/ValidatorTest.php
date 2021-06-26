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

/**
 * Class ValidatorTest
 *
 * @package SPie\LaravelJWT\Test\Unit
 */
final class ValidatorTest extends TestCase
{
    use JWTHelper;

    //region Tests

    /**
     * @return void
     */
    public function testValidateWithValidToken(): void
    {
        $token = $this->createToken();
        $constraint = $this->createContraint();
        $lcobucciValidator = $this->createLcobucciValidator();
        $this->mockLcobucciValidatorValidate($lcobucciValidator, true, $token, $constraint);

        $this->assertTrue($this->getValidator($lcobucciValidator, $constraint)->validate($token));
    }

    /**
     * @return void
     */
    public function testValidateWithoutValidToken(): void
    {
        $token = $this->createToken();
        $constraint = $this->createContraint();
        $lcobucciValidator = $this->createLcobucciValidator();
        $this->mockLcobucciValidatorValidate($lcobucciValidator, false, $token, $constraint);

        $this->assertFalse($this->getValidator($lcobucciValidator, $constraint)->validate($token));
    }

    //endregion

    /**
     * @param LcobucciValidator|null $validator
     * @param Constraint|null        $constraint
     *
     * @return Validator
     */
    private function getValidator(LcobucciValidator $validator = null, Constraint $constraint = null): Validator
    {
        return new Validator(
            $validator ?: $this->createLcobucciValidator(),
            $constraint ?: $this->createContraint()
        );
    }

    /**
     * @return LcobucciValidator|MockInterface
     */
    private function createLcobucciValidator(): LcobucciValidator
    {
        return m::spy(LcobucciValidator::class);
    }

    /**
     * @param LcobucciValidator|MockInterface $validator
     * @param bool                            $valid
     * @param Token                           $token
     * @param Constraint                      $constraint
     *
     * @return $this
     */
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
    private function createContraint(): Constraint
    {
        return m::spy(Constraint::class);
    }
}
