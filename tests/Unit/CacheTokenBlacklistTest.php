<?php

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use SPie\LaravelJWT\Blacklist\CacheTokenBlacklist;
use SPie\LaravelJWT\JWT;

/**
 * Class CacheTokenBlacklistTest
 */
class CacheTokenBlacklistTest extends TestCase
{

    use JWTHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testRevoke(): void
    {
        $arrayStore = new ArrayStore();

        $jwt = new JWT($this->createToken([], null, 1));

        $this->createCacheTokenBlacklist($arrayStore)->revoke($jwt);

        $this->assertNotEmpty($arrayStore->get(\md5($jwt->getJWT())));
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testRevokeForever(): void
    {
        $arrayStore = new ArrayStore();

        $jwt = new JWT($this->createToken());

        $this->createCacheTokenBlacklist($arrayStore)->revoke($jwt);

        $this->assertNotEmpty($arrayStore->get(\md5($jwt->getJWT())));
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIsRevoked(): void
    {
        $jwt = new JWT($this->createToken());
        $arrayStore = new ArrayStore();
        $arrayStore->put(\md5($jwt->getJWT()), (string)$jwt->getJWT(), CacheTokenBlacklist::EXPIRATION_MINUTES_DEFAULT);

        $this->assertTrue($this->createCacheTokenBlacklist($arrayStore)->isRevoked((string)$jwt->getJWT()));
    }

    /**
     * @return void
     */
    public function testIsRevokedWithoutToken(): void
    {
        $this->assertFalse($this->createCacheTokenBlacklist(new ArrayStore())->isRevoked($this->getFaker()->uuid));
    }

    //endregion

    /**
     * @param ArrayStore|null $arrayStore
     *
     * @return CacheTokenBlacklist
     */
    private function createCacheTokenBlacklist(ArrayStore $arrayStore = null): CacheTokenBlacklist
    {
        return new CacheTokenBlacklist(new Repository(
            $arrayStore ?: new ArrayStore()
        ));
    }
}
