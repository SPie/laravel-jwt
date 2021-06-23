<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validator as LcobucciValidator;
use SPie\LaravelJWT\Contracts\Validator as ValidatorContract;

/**
 * Class Validator
 *
 * @package SPie\LaravelJWT
 */
final class Validator implements ValidatorContract
{
    /**
     * @var LcobucciValidator
     */
    private LcobucciValidator $validator;

    /**
     * @var Constraint
     */
    private Constraint $constraint;

    /**
     * Validator constructor.
     *
     * @param LcobucciValidator $validator
     * @param Constraint        $constraint
     */
    public function __construct(LcobucciValidator $validator, Constraint $constraint)
    {
        $this->validator = $validator;
        $this->constraint = $constraint;
    }

    /**
     * @param Token $token
     *
     * @return bool
     */
    public function validate(Token $token): bool
    {
        return $this->validator->validate($token, $this->constraint);
    }
}
