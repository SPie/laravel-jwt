# JWT Package for Laravel

This package provides a Laravel `Guard` for JWT authentication.
It uses [`lcobucci/jwt:3.2`](https://github.com/lcobucci/jwt) to create and validate the tokens.

## Requirements
  * PHP >= 7.1
  
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
JWT_TTL=10
JWT_SIGNER=Lcobucci\JWT\Signer\Hmac\Sha256
JWT_TOKEN_PROVIDER=SPie\\LaravelJWT\\TokenProvider\\HeaderTokenProvider
JWT_TOKEN_KEY=Authorization
JWT_TOKEN_PREFIX=Bearer
```
You can also copy the `config/jwt.php` file from the repo to your projects config directory to configure JWT without an `.env` file.

**It is required to add a value for** `JWT_SECRET` **(you can use the** `jwt:generate:secret` **artisan command) and** `JWT_ISSUER`. 
For every other config a default value exists.

### Auth
You need to add an entry for the `JWTGuard` in you `config/auth.php` file. 
```php
'guards' => [

    ...
    
    'jwt' => [
        'driver' => 'jwt',
    ],
],
```

## Usage
You can use the `SPie\LaravelJWT\Auth\JWTGuard` by using dependency injection and depend on `Illuminate\Contracts\Auth\Guard`.
You can also get the `JWTGuard` by `Illuminate\Auth\AuthManager::guard($name)`, using the guard name configured in `config/auth.php`.

### User
To use your user model for authentication, it has to implement the `SPie\LaravelJWT\Contracts\JWTAuthenticatable` interface.

### Login
The `JWTGuard` provides a method to login your user by credentials. This will mark the user as logged-in in the guard and 
will create a `SPie\LaravelJWT\JWT` object.
```php
$jwtGuard->login([
    'username' => 'USERNAME',
    'password' => 'PASSWORD',
]);
 
/** @var SPie\LaravelJWT\JWT $jwt */
$jwt = $jwtGuard->getJWT();
 
/** @var SPie\LaravelJWT\Contracts\JWTAuthenticatable $user */
$user = $jwtGuard->getUser();

```
If the login fails, the `JWTGuard` will throw an `Illuminate\Auth\Access\AuthorizationException`.

### Get user by token
The `JWTGuard::user()` method gets and authenticates a user by token, provided by the request.
```php
/** @var SPie\LaravelJWT\Contracts\JWTAuthenticatable|null $user */
$user = $jwtToken->user();
```
If no token was send by request or the token was invalid, the method will return `NULL`.

### TokenProvider
You have to specify a `TokenProvider` to be able to extract a token from request.
This package includes two `TokenProvider` already: the `SPie\LaravelJWT\TokenProvider\HeaderTokenProvider` and
the `SPie\LaravelJWT\TokenProvider\CookieTokenProvider`.
Of course you can create a custom `TokenProvider`, implementing the `SPie\LaravelJWT\Contracts\TokenProvider` interface 
and specify it in the JWT config.

### JWTHandler
To create or validate JWTs, you can use the `SPie\LaravelJWT\JWTHandler`. Just use dependency injection or use the `make` 
container function.
```php
Container()::getInstance->make(SPie\LaravelJWT\JWTHandler::class)
```

#### Create JWT
To create a JWT, you have to provide a subject and an optional payload.
```php
/** @var SPie\LaravelJWT\JWT $jwt */
$jwt = $jwtHandler->createJWT('SUBJECT', ['claim1' => 'value1']);
```

#### Get valid JWT
To validate a JWT, you have to provide the token as string. You will get a `SPie\LaravelJWT\JWT` object, if the token is
valid, or a specific `JWTException`.
```php
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IiwiaWF0IjoxNTQyOTc0NzM3LCJleHAiOjE1NzQ1OTcxMzcsImF1ZCI6IiIsInN1YiI6IlRlc3QifQ.XdS6BiYD02I_1AAFeCxuO3LdeNBXLjE9TWd-G89ePOk';
 
/** @var SPie\LaravelJWT\JWT $jwt */
$jwt = $jwtHandler->getValidJWT($token);
```
Possible exceptions are possible:
  * `SPie\LaravelJWT\Exceptions\InvalidTokenException`
  * `SPie\LaravelJWT\Exceptions\InvalidSignatureException`
  * `SPie\LaravelJWT\Exceptions\TokenExpiredException`
  * `SPie\LaravelJWT\Exceptions\BeforeValidException`
  
### JWT Object
The `SPie\LaravelJWT\JWT` object is just a wrapper for `Lcobucci\JWT\Token`.
To get the string representation of the JWT, you have to call the `JWT::getJWT()` method.

## Upcoming
Future features:
  * Token revokation
  * Refresh token
