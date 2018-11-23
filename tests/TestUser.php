<?php

use SPie\LaravelJWT\Contracts\JWTAuthenticatable;

/**
 * Class TestUser
 */
class TestUser implements JWTAuthenticatable
{

    /**
     * @var string
     */
    private $authIdentifierName;

    /**
     * @var string
     */
    private $authIdentifier;

    /**
     * @var string
     */
    private $authPassword;

    /**
     * @var array
     */
    private $customClaims;

    /**
     * TestUser constructor.
     *
     * @param string $authIdentifierName
     * @param string $authIdentifier
     * @param string $authPassword
     * @param array  $customClaims
     */
    public function __construct(
        string $authIdentifierName,
        string $authIdentifier,
        string $authPassword,
        array $customClaims = []
    ) {
        $this->authIdentifierName = $authIdentifierName;
        $this->authIdentifier = $authIdentifier;
        $this->authPassword = $authPassword;
        $this->customClaims = $customClaims;
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return $this->authIdentifierName;
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->authIdentifier;
    }

    /**
     * Get the password for the user.
     *
     * @return string
     */
    public function getAuthPassword()
    {
        return $this->authPassword;
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     */
    public function getRememberToken() {}

    /**
     * Set the token value for the "remember me" session.
     *
     * @param  string $value
     *
     * @return void
     */
    public function setRememberToken($value) {}

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     */
    public function getRememberTokenName() {}

    /**
     * @return array
     */
    public function getCustomClaims(): array {
        return [];
    }
}
