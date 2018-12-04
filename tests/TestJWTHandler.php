<?php

use SPie\LaravelJWT\Exceptions\JWTException;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTHandler;

/**
 * Class TestJWTHandler
 */
class TestJWTHandler extends JWTHandler
{

    /**
     * @var JWT
     */
    private $jwt;

    /**
     * @var JWTException
     */
    private $jwtException;

    /**
     * @param JWT|null $jwt
     *
     * @return TestJWTHandler
     */
    public function setJWT(?JWT $jwt): TestJWTHandler
    {
        $this->jwt = $jwt;

        return $this;
    }

    /**
     * @param null|JWTException $jwtException
     *
     * @return TestJWTHandler
     */
    public function setJWTException(?JWTException $jwtException): TestJWTHandler
    {
        $this->jwtException = $jwtException;

        return $this;
    }

    /**
     * @param string $jwt
     *
     * @return JWT
     *
     * @throws JWTException
     */
    public function getValidJWT(string $jwt): JWT
    {
        if (!empty($this->jwtException)) {
            throw $this->jwtException;
        }

        return $this->jwt;
    }

    /**
     * @param string $subject
     * @param array  $payload
     *
     * @return JWT
     *
     * @throws \Exception
     */
    public function createJWT(string $subject, array $payload = []): JWT {
        if (!empty($this->jwt)) {
            return $this->jwt;
        }

        return parent::createJWT($subject, $payload);
    }
}
