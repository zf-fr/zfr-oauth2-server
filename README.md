# ZfrOAuth2Server

[![Build Status](https://travis-ci.org/zf-fr/zfr-oauth2-server.png)](https://travis-ci.org/zf-fr/zfr-oauth2-server)
[![Latest Stable Version](https://poser.pugx.org/zfr/zfr-oauth2-server/v/stable.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)
[![Coverage Status](https://coveralls.io/repos/zf-fr/zfr-oauth2-server/badge.png)](https://coveralls.io/r/zf-fr/zfr-oauth2-server)
[![Total Downloads](https://poser.pugx.org/zfr/zfr-oauth2-server/downloads.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/prolic/zfc-rbac)

ZfrOAuth2Server is a PHP library that implements the OAuth 2 specification. It's main goal is to be a clean, PHP 7.0+
library that aims to be used with any persistence layer of choice. It is compatible with
[PSR-7](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md) request and responses which makes
it possible to use with any framework compatible with PSR-7.

Currently, ZfrOAuth2Server does not implement the whole specification (implicit grant is missing), so you are encouraged to have a look at the doc if ZfrOAuth2Server can be used in your application. 

However, it implements the additional [token revocation](https://tools.ietf.org/html/rfc7009) specification.

Here are other OAuth2 library you can use:

- [OAuth2 Server from PHP-League](https://github.com/php-loep/oauth2-server)
- [OAuth2 Server from Brent Shaffer](https://github.com/bshaffer/oauth2-server-php)

## Requirements

- PHP 7.0 or higher

## To-do

- Write documentation
- Security audit
- Review of the whole spec
- Testing the authorization server more extensively
- Add implicit grant

## Versioning note

Please note that until I reach 1.0, I **WILL NOT** follow semantic version. This means that BC can occur between
0.1.x and 0.2.x releases. If you are using this in production, please set your dependency using 0.1.*, for instance.

## Installation

Installation is only officially supported using Composer:

```sh
php composer.phar require zfr/zfr-oauth2-server:^1.0
```

## Support

- File issues at [https://github.com/zf-fr/zfr-oauth2-server/issues](https://github.com/zf-fr/zfr-oauth2-server/issues).
- Say hello in the [prooph gitter](https://gitter.im/prolic/zfr-oauth2-server) chat.

### Configuration

Several Apache modules will strip HTTP authorization headers such as `Authorization` to try to enhance security by preventing scripts from seeing sensitive information unless the developer explicitly enables this.

Many of these modules will allow such headers if you simply add the following line to .htaccess (or the vhost directory directive).

```
CGIPassAuth on
```
since: [Apache 2.4.13](https://httpd.apache.org/docs/trunk/mod/core.html#cgipassauth)



## Framework integration

Because of its strict dependency injection architecture, ZfrOAuth2Server is hardly usable alone, as it requires
quite a lot of configuration. However, I've made a Zend Framework 2 module that abstract the whole configuration,
and make it very easy to use:

* [Zend Framework 2 module](https://github.com/zf-fr/zfr-oauth2-server-module)

If anyone want to help with a Symfony 2 bundle, I'd be glad to help.

## Documentation

ZfrOAuth2Server is based on the [RFC 6749](http://tools.ietf.org/html/rfc6749) documentation.

### Why using OAuth2?

OAuth2 is an authentication/authorization system that allows that can be used to:

* Implement a stateless authentication mechanism (useful for API)
* Allow third-party to connect to your application securely
* Securing your application through the use of scopes

OAuth2 is a dense, extensible specification that can be used for a wide number of use-cases. As of today,
ZfrOAuth2Server implements three of the four official grants: AuthorizationGrant, ClientCredentialsGrant, PasswordGrant.

### How OAuth2 works?

This documentation does not aim to explain in details how OAuth2 work. Here is [a nice resource](http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified) you can read. However, here is the basic idea of how OAuth2 works:

1. A resource owner (your JavaScript API, your mobile application...) asks for a so-called "access token" to an
 authorization server. There are several strategies that depends on the use-case. Those strategies are called
 "grants". For instance, the "password grant" assumes that the resource owner sends its username/password. In all
 cases, your authorization server responds with an access token (and an optional refresh token).
2. The client sends this access token to each request that is made to your API. It is used by a "resource server"
to map this access token to a user in your system.

Choosing the grant type depends on your application. Here are a few hints about which one to choose:

* If you are the only consumer of your API (for instance, your JavaScript application make calls to your API), you
should use the "password grant". Because you trust your application, it is not a problem to send username/password.
* If you want a third-party code to connect to your API, and that you are sure that this third-party can keep secrets
(this means the client is not a JavaScript API, or a mobile application): you can use the client credentials grant.
* If you want third-party code to connect to your API, and that those third-party applications cannot keep secret
(think about an unofficial Twitter client that connect to your Twitter account, for instance), you should use the
authorization grant.

### Using the authorization server

The authorization server goal is to accept a request, and generate token. An authorization server can deny a
request (for instance, if parameters are missing, or if username/password are incorrect).

To use an authorization server, you must first decide which grant you want to support. Some applications should
only support one type of grant, others may support all of the available grant. This is completely up to you, and
you should have a solid understanding of all those grants first. For instance, here is how you would create an
authorization server that support the authorization only:

```php
$authTokenService    = new TokenService($objectManager, $authTokenRepository, $scopeRepository);
$accessTokenService  = new TokenService($objectManager, $accessTokenRepository, $scopeRepository);
$refreshTokenService = new TokenService($objectManager, $refreshTokenRepository, $scopeRepository);

$authorizationGrant  = new AuthorizationGrant($authTokenService, $accessTokenService, $refreshTokenService);
$authorizationServer = new AuthorizationServer([$authorizationGrant]);

// Response contains the various parameters you can return
$response = $authorizationServer->handleRequest($request);
```

The request must be a valid `Psr\Http\Message\ServerRequestInterface`, and the authorization server returns a `Psr\Http\Message\ResponseInterface` object
that is compliant with the OAuth2 specification.

#### Passing a user

Most of the time, you want to associate an access token to a user. This is the only way to map a token to a user
of your system. To do this, you can pass an optional second parameter to the `handleRequest`. This class must
implements the `ZfrOAuth2\Server\Model\TokenOwnerInterface` interface:

```php
$user = new User(); // must implement TokenOwnerInterface

// ...

$response = $authorizationServer->handleRequest($request, $user);
```

#### Revoking a token 

ZfrOAuth2Server supports revoking access and refresh tokens using the [RFC 7009 specification](https://tools.ietf.org/html/rfc7009).
You can use the `handleRevocationRequest` method in the AuthorizationServer. You must pass the following two POST parameters:

* `token`: the token to remove (either access or refresh token)
* `token_hint_type`: must be either `access_token` or `refresh_token` to indicate the authorization server which token
type to revoke.

If you need to revoke a token that was issued for a non-public client (this means a client that has a secret key), then you
MUST authenticate the request using the client id and secret.

> If you try to revoke a token that does not exist, it will return 200 SUCCESS request, according to the spec. However,
if the token is valid, but cannot be deleted for any reason (database is down...), then it returns a 503 SERVICE UNAVAILABLE
error!

### Using the resource server

You can use the resource server to retrieve the access token (by automatically extracting the data from the HTTP
headers). You can also specify scope constraints when retrieving the token:

```php
$accessTokenService = new TokenService($objectManager, $accessTokenRepository, $scopeRepository);
$resourceServer     = new ResourceServer($accessTokenService);

if (!$token = $resourceServer->getAccessToken($request, ['write']) {
    // there is either no access token, or the access token is expired, or the access token does not have
    // the `write` scope
}
```

### Persistence layer

As of version 1.0 ZfrOAuth2Server has been rewritten to be persistence layer agnostic. Meaning it can by used with any prefered persistence layer.

Currently these packages provide a persistence layer;

- [ZfrOAuth2ServerDoctrine](https://github.com/zf-fr/zfr-oauth2-server-doctrine) for Doctrine 2


### Event manager

There are a lot of use cases where you would like to execute specific code when a token is created (or when it
could not be created). Such use cases include: log login, modify generic OAuth2 response to include additional fields...

To that extent, ZfrOAuth2 trigger various events in the `AuthorizationServer`. Four events are triggered:

* `ZfrOAuth2\Server\Event\AuthorizationCodeEvent::EVENT_CODE_CREATED`: event that is triggered when the auth code has
been properly created and persisted.
* `ZfrOAuth2\Server\Event\AuthorizationCodeEvent::EVENT_CODE_FAILED`: event that is triggered when an error has occurred (
wrong credentials, missing grant...).
* `ZfrOAuth2\Server\Event\TokenEvent::EVENT_TOKEN_CREATED`: event that is triggered when the access token has
been properly created and persisted.
* `ZfrOAuth2\Server\Event\TokenEvent::EVENT_TOKEN_FAILED`: event that is triggered when an error has occurred (
wrong credentials, missing grant...).

In both cases, the `TokenEvent` or `AuthorizationCodeEvent` event lets you access to the request, the response body
and the access token/authorization code (if available).

Here is an example:

#### Zend Framework 2 users

Zend Framework 2 users can take advantage of the shared event manager, and attach listeners in their Module.php
class as shown below:

```php
use ZfrOAuth2\Server\Event\TokenEvent;

class Module
{
    public function onBootstrap(EventInterface $event)
    {
        /* @var \Zend\Mvc\Application $application */
        $application   = $event->getTarget();
        $eventManager  = $application->getEventManager();
        $sharedManager = $eventManager->getSharedManager();

        $sharedManager->attach(
            'ZfrOAuth2\Server\AuthorizationServer',
            TokenEvent::EVENT_TOKEN_CREATED,
            [$this, 'tokenCreated']
        );

        $sharedManager->attach(
            'ZfrOAuth2\Server\AuthorizationServer',
            TokenEvent::EVENT_TOKEN_FAILED,
            [$this, 'tokenFailed']
        );
    }

    public function tokenCreated(TokenEvent $event)
    {
        // Get the response
        $response = $event->getResponse();
        // ...

        // Response is a PSR-7 compliant response, so you modify it
        $response = $response->withHeader(...);

        // Do not forget to set back the response, as PSR-7 are immutable
        $event->setResponse($response);
    }

    public function tokenFailed(TokenEvent $event)
    {
        // We can inspect the response to know what happen and log the failure
        $body = $event->getResponse()->getBody();
    }
}
```

#### Other users

For other users, you can manually retrieve the event manager from the authorization server, and attach
your listener there:

```php
use ZfrOAuth2\Server\Event\TokenEvent;

$eventManager = $authorizationServer->getEventManager();
$eventManager->attach(TokenEvent::EVENT_TOKEN_CREATED, function(TokenEvent $event) {
    // Do things
}
```

You are responsible to wire everything in your application.

#### Second level cache

Scope and tokens are marked cacheable to take advantage of Doctrine 2.5 ORM second level cache. However, you
need to configure the regions yourself.
