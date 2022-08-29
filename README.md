# ZfrOAuth2Server

[![Continuous Integration](https://github.com/zf-fr/zfr-oauth2-server/actions/workflows/continuous-integration.yml/badge.svg)](https://github.com/zf-fr/zfr-oauth2-server/actions/workflows/continuous-integration.yml)
[![Latest Stable Version](https://poser.pugx.org/zfr/zfr-oauth2-server/v/stable.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)
[![Coverage Status](https://coveralls.io/repos/github/zf-fr/zfr-oauth2-server/badge.svg?branch=master)](https://coveralls.io/github/zf-fr/zfr-oauth2-server?branch=master)
[![Total Downloads](https://poser.pugx.org/zfr/zfr-oauth2-server/downloads.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/prolic/zfr-oauth2-server)

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

- PHP 7.2 or higher

## To-do

- Write documentation
- Security audit
- Review of the whole spec
- Testing the authorization server more extensively
- Add implicit grant

## Versioning note

Please note that until we reach 1.0, we **WILL NOT** follow semantic version. This means that BC can occur between
0.1.x and 0.2.x releases.

The current pre release of a completely rewritten version, is it not copatible with the previous implementation - which is considered EOL - see the [legacy-0.7](https://github.com/zf-fr/zfr-oauth2-server/tree/legacy-0.7) branch. 

See the [CHANGELOG](CHANGELOG.md)

## Installation

use Composer to install:

```sh
php composer.phar require zfr/zfr-oauth2-server:^0.9-beta
```

## Support

- File issues at [https://github.com/zf-fr/zfr-oauth2-server/issues](https://github.com/zf-fr/zfr-oauth2-server/issues).
- Say hello in our [gitter](https://gitter.im/prolic/zfr-oauth2-server) chat.

## Configuration

Several Apache modules will strip HTTP authorization headers such as `Authorization` to try to enhance security by preventing scripts from seeing sensitive information unless the developer explicitly enables this.

Many of these modules will allow such headers if you simply add the following line to .htaccess (or the vhost directory directive).

```
CGIPassAuth on
```
since: [Apache 2.4.13](https://httpd.apache.org/docs/trunk/mod/core.html#cgipassauth)


## Documentation

ZfrOAuth2Server is based on the [RFC 6749](http://tools.ietf.org/html/rfc6749) documentation.

### Why use OAuth2?

OAuth2 is an authentication/authorization system that allows that can be used to:

* Implement a stateless authentication mechanism (useful for API)
* Allow third-party to connect to your application securely
* Securing your application through the use of scopes

OAuth2 is a dense, extensible specification that can be used for a wide number of use-cases. As of today,
ZfrOAuth2Server implements three of the four official grants: AuthorizationGrant, ClientCredentialsGrant, PasswordGrant. Additionally a RefreshTokenGrant is provided to obtain new access tokens. ImplicitGrant and JWTTokens are forthcoming (help wanted).

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

The AuthorizationServerMiddleware is able to do this for you and retrieve a user instance from a (configurable) request attribute. It is up to you to provide middleware which runs with a higher priority to add a TokenOwnerInterface instance to the request attribute. 

Example of such a implementation which uses LaminasAuthentication and a TemplateRenderer from Mezzio.

```
final class OAuth2AuthorizationFlow
{
    /**
     * @var AuthenticationService
     */
    private $authenticationService;

    /**
     * @var ClientService
     */
    private $clientService;

    /**
     * @var TemplateRendererInterface
     */
    private $template;

    public function __construct(
        AuthenticationService $authenticationService,
        ClientService $clientService,
        TemplateRendererInterface $template
    ) {
        $this->authenticationService = $authenticationService;
        $this->clientService         = $clientService;
        $this->template              = $template;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $out = null)
    {
        if ($this->authenticationService->hasIdentity()) {
            $request = $request->withAttribute('owner', $this->authenticationService->getIdentity());
        }

        if ($request->getMethod() === 'POST') {
            $post     = $request->getParsedBody();
            $approved = filter_var($post['approved'], FILTER_VALIDATE_BOOLEAN);

            if ($approved) {
                return $out($request, $response);
            }
        }

        $data  = [];
        $query = $request->getUri()->getQuery();
        parse_str($query, $data['query']);

        $data['client'] = $this->clientService->getClient($data['query']['client_id']);

        return new HtmlResponse($this->template->render('app::oauth2/authorize-request', $data));
    }
}
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

The ResourceServerMiddleware is able to do this for you, simply have it run before any other middleware.

Example mezzio expressive route configuration.

```
[
            'name'            => 'command::commerce::create-store',
            'path'            => '/commerce/create-store',
            'middleware'      => [
                ResourceServerMiddleware::class,
                MyActionMiddleware::class,
            ],
            'allowed_methods' => ['OPTIONS', 'POST'],
        ],
```         

### Persistence layer

As of version 0.8-beta1 ZfrOAuth2Server has been rewritten to be persistence layer agnostic. Meaning it can by used with any prefered persistence layer.

Currently these packages provide a persistence layer;

- [ZfrOAuth2ServerDoctrine](https://github.com/zf-fr/zfr-oauth2-server-doctrine) for Doctrine 2
