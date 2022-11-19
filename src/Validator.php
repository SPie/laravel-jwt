<?php

namespace SPie\LaravelJWT;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validator as LcobucciValidator;
use SPie\LaravelJWT\Contracts\Validator as ValidatorContract;

final class Validator implements ValidatorContract
{
    private LcobucciValidator $validator;

    private Constraint $constraint;

    public function __construct(LcobucciValidator $validator, Constraint $constraint)
    {
        $this->validator = $validator;
        $this->constraint = $constraint;
    }

    public function validate(Token $token): bool
    {
        return $this->validator->validate($token, $this->constraint);
    }
}
