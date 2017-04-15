# Changelog

## dev-master

## v0.8.0-beta3

* Implements [PSR-15](https://github.com/php-fig/fig-standards/tree/master/proposed/http-middleware)

## v0.8.0-beta2

* When an token can't be found the returned error response by the resource server middleware is now in a similar format to other errors. This might BC if your client depends on the error key in the message.
* Added an server option so the request attribute for tokens can be configured

## v0.8.0-beta1

BC! Pre release of a completely rewritten library. It focusses on core OAuth2 functionality and has been decoupled from persistence. If you still need the previous implementation - which is considered EOL - see the [legacy-0.7](https://github.com/zf-fr/zfr-oauth2-server/tree/legacy-0.7) branch

* PHP7+ only
* 100% test coverage
* Uses [Zend\Diactoros](https://github.com/zendframework/zend-diactoros) to generate  [PSR-7 (Http Message)](https://github.com/php-fig/http-message) implementation.
* Uses [PSR-11 (Container)](https://github.com/php-fig/container) for dependency injection containers.
* Eventing has been removed
* Persistence has been decoupled, see our doctrine integration [ZfrOAuth2ServerDoctrine](https://github.com/zf-fr/zfr-oauth2-server-doctrine)
* Provides 5 Services
	* ZfrOAuth2\Server\Service\AccessTokenService
	* ZfrOAuth2\Server\Service\AuthorizationCodeService
	* ZfrOAuth2\Server\Service\ClientService
	* ZfrOAuth2\Server\Service\RefreshTokenService
	* ZfrOAuth2\Server\Service\ScopeService
* Provides 4 PSR7 Middleware's which are really nice but optional
	* ZfrOAuth2\Server\AuthorizationServerMiddleware
	* ZfrOAuth2\Server\ResourceServerMiddleware
	* ZfrOAuth2\Server\RevocationRequestMiddleware
	* ZfrOAuth2\Server\TokenRequestMiddleware

## v0.7.1

* Now properly triggers an `EVENT_CODE_CREATED` event instead of `EVENT_CODE_FAILED` when response is between 200 and 399 (previously, 
as 302 Redirect used to trigger a failed event, although it created an authorization code).

## v0.7.0

* [BC] PHP minimum version has been bumped to 5.5. As a consequence, Zend\Crypt dependency has been removed as some of 
features are built-in into PHP 5.5.
  
* [BC] Instead of Zend\Http requests and responses, the module now uses PSR7 requests and responses, for increased 
compatibility. If you are using the ZF2 module, this should be completely transparent to you.
  
* [BC] Contrary to Zend\Http requests and responses, PSR7 are stateless. If you are using events to modify the response, 
you will need to use a different way.
  
In ZfrOAuth2Server 0.6:

```php
public function tokenCreated(TokenEvent $event)
{
    // We can log the access token
    $accessToken = $event->getAccessToken();
    // ...
  
    // Or we can alter the response body, if we need to
    $body                 = $event->getResponseBody();
    $body['custom_field'] = 'bar';
  
    // Update the body
    $event->setResponseBody($body);
}
```

In ZfrOAuth2Server 0.7+:

```php
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
```

* Interfaces for ResourceServer and AuthorizationServer has been added, for easier testing.
  
## v0.6.0

* In previous versions, ZfrOAuth2 would trigger an "InvalidAccessTokenException" if you'd try to call the `getToken` 
when no token was specified in either Authorization header or query param. Now, ZfrOAuth2 will simply return null 
(because no token was explicitly set). However, this exception will be trigger IF an access token is indeed given, but 
does not exist in your database, is expired or does not match scopes.

## v0.5.0

* Support for token revocation by implementing [RFC7009 specification](https://tools.ietf.org/html/rfc7009)

## v0.4.0

* Allow multiple redirect URI for client (there is a minor table schema change, as a consequence)
* Fix a potential security issue by being more restrictive on the redirect URI when creating an authorization code. Now, 
if someone send a custom redirect_uri in the query params, the OAuth2 server will first check if the given redirect URI is 
in the list of the authorized redirect URIs by the client. If that's not the case, an InvalidRequest exception will be 
returned, and no authorization code will be generated.
  
## v0.3.0

* Add support for the ZF2 event manager. You can now attach listeners that are called whenever a new authorization code is 
created or failed, or when a new access token is created or failed.

## v0.2.0

* [BC] The `isRequestValid` from the ResourceServer is now gone in favour of a simpler approach: you just need to call 
the `getAccessToken` from the ResourceServer (with optional scopes), and null will be returned if the token is either expired, does 
not exist or does not match given scopes.

## v0.1.1

* Tokens do not contain \ and / characters anymore (as it can lead to problems when the token is passed as a query param).

## v0.1.0

* First release!