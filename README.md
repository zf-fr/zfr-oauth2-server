# ZfrOAuth2Server

[![Build Status](https://travis-ci.org/zf-fr/zfr-oauth2-server.png)](https://travis-ci.org/zf-fr/zfr-oauth2-server)
[![Latest Stable Version](https://poser.pugx.org/zfr/zfr-oauth2-server/v/stable.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)
[![Coverage Status](https://coveralls.io/repos/zf-fr/zfr-oauth2-server/badge.png)](https://coveralls.io/r/zf-fr/zfr-oauth2-server)
[![Scrutinizer Quality Score](https://scrutinizer-ci.com/g/zf-fr/zfr-oauth2-server/badges/quality-score.png?s=be36235c9898cfc55044f58d9bba789d2d4d102e)](https://scrutinizer-ci.com/g/zf-fr/zfr-oauth2-server/)
[![Total Downloads](https://poser.pugx.org/zfr/zfr-oauth2-server/downloads.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)

ZfrOAuth2Server is a PHP library that aims to implement the OAuth 2 specification strictly. Contrary to other
libraries, it assumes you are using Doctrine, and provide various services based on Doctrine interfaces.

Currently, it's more of a proof of concept to implement a simpler and cleaner OAuth 2 server implementation. It
does not support yet the Implicit grant. If you want to help, please contribute!

If you need a full featured project, that was tested by thousands of people, I suggest you to have a look
at one of those two PHP libraries:

- [OAuth2 Server from PHP-League](https://github.com/php-loep/oauth2-server)
- [OAuth2 Server from Brent Shaffer](https://github.com/bshaffer/oauth2-server-php)

## Requirements

- PHP 5.4 or higher

## To-do

- Better documentation
- Review of the whole spec
- Testing the authorization server more extensively

## Versioning note

Please note that until I reach 1.0, I **WILL NOT** follow semantic version. This means that BC can occur between
0.1.x and 0.2.x releases. If you are using this in production, please set your dependency using 0.1.*, for instance.

## Installation

Installation is only officially supported using Composer:

```sh
php composer.phar require zfr/zfr-oauth2-server:0.1.*
```

## Framework integration

Here are various official integrations with ZfrOAuth2Server:

* [Zend Framework 2 module](https://github.com/zf-fr/zfr-oauth2-server-module)

## Documentation

ZfrOAuth2Server is based on the [RFC 6749](http://tools.ietf.org/html/rfc6749) for OAuth 2.

### Using the authorization server

The authorization server allows you to authorize a request and generate a token. To create an authorization server,
you need first to create grants. A grant is a flow that allows to create tokens. Each flow has its own use case.
Currently, ZfrOAuth2 supports the following grants: authorization grant, client credentials grant, password grant
and refresh token grant:

```php
$authTokenService    = new TokenService($objectManager, $authTokenRepository, $scopeRepository);
$accessTokenService  = new TokenService($objectManager, $accessTokenRepository, $scopeRepository);
$refreshTokenService = new TokenService($objectManager, $refreshTokenRepository, $scopeRepository);

$authorizationGrant  = new AuthorizationGrant($authTokenService, $accessTokenService, $refreshTokenService);
$authorizationServer = new AuthorizationServer([$authorizationGrant]);

// Response contains the various parameters you can return
$response = $authorizationServer->handleRequest($request);
```

#### Passing a user

Most of the time, you want to associate an access token to a user. To do this, you can pass an optional second
parameter to the `handleRequest`. This class must implements the `ZfrOAuth2\Server\Entity\TokenOwnerInterface`
interface:

```php
$user = new User(); // must implement TokenOwnerInterface

// ...

$response = $authorizationServer->handleRequest($request, $user);
```

### Using the resource server

You can use the resource server to retrieve the access token (by automatically extract the data from the HTTP
headers). You can also use the resource server to validate the access token against scopes:

```php
$accessTokenService = new TokenService($objectManager, $accessTokenRepository, $scopeRepository);
$resourceServer     = new ResourceServer($accessTokenService);

if (!$resourceServer->isRequestValid($request, ['write']) {
    // there is either no access token, or the access token is expired, or the access token does not have
    // the `write` scope
}
```

You can also manually retrieve the access token:

```php
$accessToken = $resourceServer->getAccessToken($request);
```

### Doctrine

ZfrOAuth2Server is built to be used with Doctrine (either ORM or ODM). Out of the box, it provides ORM mapping for
Doctrine (in the `config/doctrine` folder).
