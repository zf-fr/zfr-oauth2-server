<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace ZfrOAuth2\Server\Grant;

use Zend\Http\Request as HttpRequest;
use Zend\Http\Response as HttpResponse;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\AuthorizationCode;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * Implementation of the authorization grant
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationGrant extends AbstractGrant implements AuthorizationServerAwareInterface
{
    use AuthorizationServerAwareTrait;

    /**
     * @var TokenService
     */
    protected $authorizationCodeService;

    /**
     * Access token service (used to create access token)
     *
     * @var TokenService
     */
    protected $accessTokenService;

    /**
     * Refresh token service (used to create refresh token)
     *
     * @var TokenService
     */
    protected $refreshTokenService;

    /**
     * @param TokenService $authorizationCodeService
     * @param TokenService $accessTokenService
     * @param TokenService $refreshTokenService
     */
    public function __construct(
        TokenService $authorizationCodeService,
        TokenService $accessTokenService,
        TokenService $refreshTokenService
    ) {
        $this->authorizationCodeService = $authorizationCodeService;
        $this->accessTokenService       = $accessTokenService;
        $this->refreshTokenService      = $refreshTokenService;
    }

    /**
     * {@inheritDoc}
     * @throws OAuth2Exception
     */
    public function createAuthorizationResponse(HttpRequest $request, Client $client, TokenOwnerInterface $owner = null)
    {
        // We must validate some parameters first
        $responseType = $request->getQuery('response_type');

        if ($responseType !== $this->getResponseType()) {
            throw OAuth2Exception::invalidRequest(sprintf(
                'The desired grant type must be "code", but "%s" was given',
                $responseType
            ));
        }

        // We try to fetch the redirect URI from query param as per spec, and if none found, we just use
        // the first redirect URI defined in the client
        $redirectUri = $request->getQuery('redirect_uri', $client->getRedirectUris()[0]);

        // If the redirect URI cannot be found in the list, we throw an error as we don't want the user
        // to be redirected to an unauthorized URL
        if (!$client->hasRedirectUri($redirectUri)) {
            throw OAuth2Exception::invalidRequest('Redirect URI does not match the registered one');
        }

        // Scope and state allow to perform additional validation
        $scope = $request->getQuery('scope');
        $state = $request->getQuery('state');

        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setRedirectUri($redirectUri);

        $this->populateToken($authorizationCode, $client, $owner, $scope);
        $authorizationCode = $this->authorizationCodeService->createToken($authorizationCode);

        $uri = http_build_query(array_filter([
            'code'  => $authorizationCode->getToken(),
            'state' => $state
        ]));

        $response = new HttpResponse();
        $response->getHeaders()->addHeaderLine('Location', $redirectUri . '?' . $uri);
        $response->setStatusCode(302); // here it's a redirection!

        // Set the authorization code in metadata so it can be retrieved for events
        $response->setMetadata('authorizationCode', $authorizationCode);

        return $response;
    }

    /**
     * {@inheritDoc}
     * @throws OAuth2Exception
     */
    public function createTokenResponse(HttpRequest $request, Client $client = null, TokenOwnerInterface $owner = null)
    {
        $code = $request->getPost('code');

        if (null === $code) {
            throw OAuth2Exception::invalidRequest('Could not find the authorization code in the request');
        }

        /* @var \ZfrOAuth2\Server\Entity\AuthorizationCode  $authorizationCode */
        $authorizationCode = $this->authorizationCodeService->getToken($code);

        if (null === $authorizationCode || $authorizationCode->isExpired()) {
            throw OAuth2Exception::invalidGrant('Authorization code cannot be found or is expired');
        }

        if ($authorizationCode->getClient()->getId() !== $request->getPost('client_id')) {
            throw OAuth2Exception::invalidRequest(
                'Authorization code\'s client does not match with the one that created the authorization code'
            );
        }

        // If owner is null, we reuse the same as the authorization code
        $owner = $owner ?: $authorizationCode->getOwner();

        // Everything is okey, let's start the token generation!
        $scopes      = $authorizationCode->getScopes(); // reuse the scopes from the authorization code
        $accessToken = new AccessToken();

        $this->populateToken($accessToken, $client, $owner, $scopes);
        $accessToken = $this->accessTokenService->createToken($accessToken);

        // Before generating a refresh token, we must make sure the authorization server supports this grant
        $refreshToken = null;

        if ($this->authorizationServer->hasGrant('refresh_token')) {
            $refreshToken = new RefreshToken();

            $this->populateToken($refreshToken, $client, $owner, $scopes);
            $refreshToken = $this->refreshTokenService->createToken($refreshToken);
        }

        return $this->prepareTokenResponse($accessToken, $refreshToken);
    }

    /**
     * {@inheritDoc}
     */
    public function getType()
    {
        return 'authorization_code';
    }

    /**
     * {@inheritDoc}
     */
    public function getResponseType()
    {
        return 'code';
    }

    /**
     * {@inheritDoc}
     */
    public function allowPublicClients()
    {
        return true;
    }
}
