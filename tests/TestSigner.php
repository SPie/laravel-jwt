<?php

use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

/**
 * Class TestSigner
 */
class TestSigner implements Signer
{

    /**
     * Returns the algorithm id
     *
     * @return string
     */
    public function getAlgorithmId() {}

    /**
     * Apply changes on headers according with algorithm
     *
     * @param array $headers
     */
    public function modifyHeader(array &$headers) {}

    /**
     * Returns a signature for given data
     *
     * @param string     $payload
     * @param Key|string $key
     *
     * @return Signature
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function sign($payload, $key) {}

    /**
     * Returns if the expected hash matches with the data and key
     *
     * @param string     $expected
     * @param string     $payload
     * @param Key|string $key
     *
     * @return boolean
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function verify($expected, $payload, $key) {}
}
