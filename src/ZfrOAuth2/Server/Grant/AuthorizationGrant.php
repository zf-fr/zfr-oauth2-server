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
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * Implementation of the authorization grant
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationGrant implements GrantInterface, AuthorizationServiceAwareInterface
{
    use AuthorizationServerAwareTrait;

    /**
     * Constants for the authorization grant
     */
    const GRANT_TYPE          = 'authorization_code';
    const GRANT_RESPONSE_TYPE = 'code';

    /**
     * @var AuthorizationCodeService
     */
    protected $authorizationCodeService;

    /**
     * Access token service (used to create access token)
     *
     * @var AccessTokenService
     */
    protected $accessTokenService;

    /**
     * Refresh token service (used to create refresh token)
     *
     * @var RefreshTokenService
     */
    protected $refreshTokenService;

    /**
     * @param AuthorizationCodeService $authorizationCodeService
     * @param AccessTokenService       $accessTokenService
     * @param RefreshTokenService      $refreshTokenService
     */
    public function __construct(
        AuthorizationCodeService $authorizationCodeService,
        AccessTokenService $accessTokenService,
        RefreshTokenService $refreshTokenService
    ) {
        $this->authorizationCodeService = $authorizationCodeService;
        $this->accessTokenService       = $accessTokenService;
        $this->refreshTokenService      = $refreshTokenService;
    }

    /**
     * {@inheritDoc}
     * @throws OAuth2Exception
     */
    public function createAuthorizationResponse(HttpRequest $request, Client $client)
    {
        // We must validate some parameters first
        $responseType = $request->getQuery('response_type');

        if ($responseType !== self::GRANT_RESPONSE_TYPE) {
            throw OAuth2Exception::invalidRequest(sprintf(
                'The desired grant type must be "code", but "%s" was given',
                $responseType
            ));
        }

        // If a redirect URI is specified as a GET parameter, it overrides the one define in the client
        $redirectUri = $request->getQuery('redirect_uri') ?: $client->getRedirectUri();

        // Scope and state allow to perform additional validation
        $scope = $request->getQuery('scope');
        $state = $request->getQuery('state');

        $authorizationCode = $this->authorizationCodeService->createToken($client, $client, $scope);

        $uri = http_build_query(array_filter([
            'code'  => $authorizationCode->getToken(),
            'scope' => $scope,
            'state' => $state
        ]));

        $response = new HttpResponse();
        $response->getHeaders()->addHeaderLine('Location', $redirectUri . '?' . $uri);
        $response->setStatusCode(302); // here it's a redirection!

        return $response;
    }

    /**
     * {@inheritDoc}
     * @throws OAuth2Exception
     */
    public function createTokenResponse(HttpRequest $request, Client $client)
    {
        $code = $request->getPost('code');

        if (null === $code) {
            throw OAuth2Exception::invalidRequest('Could not find the authorization code in the request');
        }

        // We need to get authorization code to perform additional validations
        $authorizationCode = $this->authorizationCodeService->getToken($code);

        if (null === $authorizationCode || $authorizationCode->isExpired()) {
            throw OAuth2Exception::invalidGrant('Authorization code cannot be found or is expired');
        }

        if ($authorizationCode->getRedirectUri() !== $request->getPost('redirect_uri')) {
            throw OAuth2Exception::invalidRequest(
                'Redirect URI does not match with the one that was issued when creating the authorization code'
            );
        }

        if ($authorizationCode->getClient()->getId() !== $request->getPost('client_id')) {
            throw OAuth2Exception::invalidRequest(
                'Authorization code client does not match with the one that created the authorization code'
            );
        }

        // Okey, everything is okey, let's start the token generation!
        $scope       = $request->getPost('scope');
        $accessToken = $this->accessTokenService->createToken($client, $client, $scope);

        $responseBody = [
            'access_token' => $accessToken->getToken(),
            'token_type'   => 'Bearer',
            'expires_in'   => $accessToken->getExpiresIn()
        ];

        // Before generating a refresh token, we must make sure the authorization server supports this grant
        if ($this->authorizationServer->hasGrant(RefreshTokenGrant::GRANT_TYPE)) {
            $refreshToken                  = $this->refreshTokenService->createToken($client, $client, $scope);
            $responseBody['refresh_token'] = $refreshToken->getToken();
        }

        // We can generate the response!
        $response = new HttpResponse();
        $response->setContent(json_encode($responseBody));

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    public function allowPublicClients()
    {
        return true;
    }
}
