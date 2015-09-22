# Changelog

## v0.8.0

* ZfrOAuth2Server now integrates with [Zend\Stratigility](https://github.com/zendframework/zend-stratigility), and provide simple
middlewares to cover authorization and authentication. This is entirely optional.

This is achieved through two middlewares that implement `Zend\Stratigility\MiddlewareInterface`:

    - `ZfrOAuth2\Server\AuthorizationServerMiddleware`: when piped, it will add three endpoints (`/authorize`, `/token`, `/revoke`) that
    handle the creation of token, revocation...
    - `ZfrOAuth2\Server\ResourceServerMiddleware`: if you are using `Zend\Expressive`, that's a middleware that you could attach as
    a `pre_routing` middleware. What it does is inspecting the request, and extracting the token, and set it as the `oauth_token` attribute

* [BC] `deleteExpiredTokens` has been removed from the TokenService. The reason is that it relied on `Selectable` Doctrine's interface, and
couldn't take advantage of batch optimization deletions in database. You should instead use a more reliable and efficient way to delete
expired tokens (either through a CRON task, or database scheduling manager).

* [BC] The `isTokenValid` method has been removed from the ResourceServer. Use the `isValid` method from the token instead.

* Tokens now have a `isValid` method to check if a given token (either authorization, access or refresh) is valid against
some scopes.

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