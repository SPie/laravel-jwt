<?php

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * Class TestUserProvider
 */
class TestUserProvider implements UserProvider
{

    /**
     * @var Authenticatable|null
     */
    private $user;

    /**
     * @var bool
     */
    private $validCredentials;

    /**
     * @param Authenticatable|null $user
     *
     * @return TestUserProvider
     */
    public function setUser(?Authenticatable $user): TestUserProvider
    {
        $this->user = $user;

        return $this;
    }

    /**
     * @param bool $validCredentials
     *
     * @return TestUserProvider
     */
    public function setValidCredentials(bool $validCredentials): TestUserProvider
    {
        $this->validCredentials = $validCredentials;

        return $this;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed $identifier
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        return $this->user;
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string $token
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        return $this->user;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  string                                     $token
     *
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token) {}

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        return $this->user;
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  array                                      $credentials
     *
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return (isset($this->user) && $this->validCredentials);
    }
}
