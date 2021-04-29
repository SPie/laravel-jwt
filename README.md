# JWT Package for Laravel
[![Build Status](https://travis-ci.org/spie/laravel-jwt.svg?branch=master)](https://travis-ci.org/spie/laravel-jwt)
[![Coverage Status](https://coveralls.io/repos/github/SPie/laravel-jwt/badge.svg?branch=master)](https://coveralls.io/github/SPie/laravel-jwt?branch=master)
[![StyleCI](https://github.styleci.io/repos/158879350/shield?branch=master)](https://github.styleci.io/repos/158879350)

This package provides a Laravel `Guard` for JWT authentication.

This package provides a access and refresh token workflow. You need to create an access token first. With the access token
you can issue a refresh token. Then this refresh token can be used to create access tokens if required.

## Requirements
  * PHP >= 7.4
  * [Laravel Components](https://github.com/laravel/framework) >= 7
  * [lcobucci/jwt](https://github.com/lcobucci/jwt) ^3.2
  
## Installation
Just pull the package with composer
```
composer require spie/laravel-jwt
```
### Laravel
Add the `SPie\LaravelJWT\Providers\LaravelServiceProvider` to the `providers` array in `config/app.php`.
```php
'providers' => [
    ...
    SPie\LaravelJWT\Providers\LaravelServiceProvider::class
],
```

### Lumen
In `bootstrap/app.php` add `Illuminate\Auth\AuthServiceProvider` and `SPie\LaravelJWT\Providers\LumenServiceProvider`.
```php
...
    
$app->register(Illuminate\Auth\AuthServiceProvider::class);
    
$app->register(SPie\LaravelJWT\Providers\LumenServiceProvider::class);
    
...
```

## Configuration
### JWT

You can configure the JWT package in your `.env` file. You can find the available config options in the `.env.example` file.
```ini
JWT_SECRET=
JWT_ISSUER=App
JWT_SIGNER=Lcobucci\JWT\Signer\Hmac\Sha256
JWT_ACCESSS_TOKEN_PROVIDER=SPie\LaravelJWT\TokenProvider\HeaderTokenProvider
JWT_ACCESS_TOKEN_TTL=10
JWT_ACCESS_TOKEN_KEY=Authorization
JWT_BLACKLIST=SPie\LaravelJWT\Blacklist\CacheTokenBlacklist
JWT_REFRESH_TOKEN_PROVIDER=SPie\LaravelJWT\TokenProvider\CookieTokenProvider
JWT_REFRESH_TOKEN_TTL=
JWT_REFRESH_TOKEN_KEY=refresh-token
JWT_REFRESH_TOKEN_REPOSITORY=
JWT_IP_CHECK_ENABLED=
```
You can also copy the `config/jwt.php` file from the repo to your projects config directory to configure JWT without an `.env` file.

**It is required to add a value for** `JWT_SECRET` **and** `JWT_ISSUER`. 
For every other config a default value exists.

### Auth
You need to add an entry for the `JWTGuard` in your `config/auth.php` file. 
```php
'guards' => [

    ...
    
    'jwt' => [
        'driver' => 'jwt',
    ],
],
```

## Usage
You can use the `SPie\LaravelJWT\Auth\JWTGuard` by using dependency injection and depend on `Illuminate\Contracts\Auth\Guard`, but you have to bind the `JWTGuard` to
`SPie\LaravelJWT\Auth\JWTGuard` to `Illuminate\Contracts\Auth\Guard` in your `ServiceProvider`.
You can also get the `JWTGuard` by `Illuminate\Auth\AuthManager::guard($name)`, using the guard name configured in `config/auth.php`.

### User
To use your user model for authentication, it has to implement the `SPie\LaravelJWT\Contracts\JWTAuthenticatable` interface.

### Login
To Login use the `login` method provided by `Illuminate\Contracts\Auth\StatefulGuard`. After that you can get the Access and Refresh token by the `getAccessToken` and
`getRefreshToken` methods. 

### Logout
The `JWTGuard::logout()` method will unset the `$jwt` and `$user` property.
If a `TokenBlacklist` is configured, the token will be revoked. If a refresh token was used, it will get revoked.

### TokenProvider
You have to specify a `TokenProvider` to be able to extract a token from request.
This package includes two `TokenProvider` already: the `SPie\LaravelJWT\TokenProvider\HeaderTokenProvider` and
the `SPie\LaravelJWT\TokenProvider\CookieTokenProvider`.
Of course, you can create a custom `TokenProvider`, implementing the `SPie\LaravelJWT\Contracts\TokenProvider` interface 
and specify it in the JWT config.
You have to specify a `TokenProvider` for refresh tokens too.

### JWTHandler
To create or validate JWTs, you can use the `SPie\LaravelJWT\JWTHandler`.

#### Create JWT
To create a JWT, you have to provide a subject and an optional payload and TTl.
```php
/** @var SPie\LaravelJWT\JWT $jwt */
$jwt = $jwtHandler->createJWT('SUBJECT', ['claim1' => 'value1'], );
```

#### Get valid JWT
To validate a JWT, you have to provide the token as string. You will get a `SPie\LaravelJWT\JWT` object, if the token is
valid, or a specific `JWTException`.
```php
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IiwiaWF0IjoxNTQyOTc0NzM3LCJleHAiOjE1NzQ1OTcxMzcsImF1ZCI6IiIsInN1YiI6IlRlc3QifQ.XdS6BiYD02I_1AAFeCxuO3LdeNBXLjE9TWd-G89ePOk';
 
/** @var SPie\LaravelJWT\JWT $jwt */
$jwt = $jwtHandler->getValidJWT($token);
```
Possible exceptions are:
  * `SPie\LaravelJWT\Exceptions\InvalidTokenException`
  * `SPie\LaravelJWT\Exceptions\InvalidSignatureException`
  * `SPie\LaravelJWT\Exceptions\TokenExpiredException`
  * `SPie\LaravelJWT\Exceptions\BeforeValidException`

If the setting `JWT_IP_CHECK_ENABLED` is set, the IP address will be compared with the one. If they don't match, the user
is not authenticated.
  
### JWT Object
The `SPie\LaravelJWT\JWT` object is just a wrapper for `Lcobucci\JWT\Token`.
To get the string representation of the JWT, you have to call the `JWT::getJWT()` method.

### TokenBlacklist
The `JWTGuard` can use a token blacklist. The token blacklist has to implement the `SPie\LaravelJWT\Contracts\TokenBlacklist` 
interface. The interface provide two methods: `revoke(SPie\LaravelJWT\JWT $jwt)` and `isRevoked(string $jwt)`.
The `revoke` method will store the JWT until it would expire, or forever if no expiration date is set.
The `isRevoked` method will check for a revoked token.

### RefreshTokenRepository
You have to implement the `SPie\LaravelJWT\RefreshTokenRepository` if you want to use refresh tokens. The `RefreshTokenRepository`
will store and revoke the refresh tokens if needed and also checks if a refresh token is already revoked.
