<?php

declare(strict_types=1);

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

use Laminas\Diactoros\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\AuthorizationServerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\AuthorizationCode;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

use function array_filter;
use function explode;
use function http_build_query;
use function is_string;
use function sprintf;

/**
 * Implementation of the authorization grant
 *
 * @licence MIT
 */
class AuthorizationGrant extends AbstractGrant implements AuthorizationServerAwareInterface
{
    public const GRANT_TYPE          = 'authorization_code';
    public const GRANT_RESPONSE_TYPE = 'code';

    private AuthorizationCodeService $authorizationCodeService;

    /**
     * An AuthorizationServer will inject itself into the grant when it is constructed
     */
    private ?AuthorizationServerInterface $authorizationServer = null;

    /**
     * Access token service (used to create access token)
     */
    private AccessTokenService $accessTokenService;

    /**
     * Refresh token service (used to create refresh token)
     */
    private RefreshTokenService $refreshTokenService;

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
     * @throws OAuth2Exception (invalid_request) When grant type was not 'code'.
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $queryParams = $request->getQueryParams();

        // We must validate some parameters first
        $responseType = $queryParams['response_type'] ?? null;

        if ($responseType !== self::GRANT_RESPONSE_TYPE) {
            throw OAuth2Exception::invalidRequest(sprintf(
                'The desired grant type must be "code", but "%s" was given',
                $responseType
            ));
        }

        // We try to fetch the redirect URI from query param as per spec, and if none found, we just use
        // the first redirect URI defined in the client
        $redirectUri = $queryParams['redirect_uri'] ?? $client->getRedirectUris()[0];

        // If the redirect URI cannot be found in the list, we throw an error as we don't want the user
        // to be redirected to an unauthorized URL
        if (! $client->hasRedirectUri($redirectUri)) {
            throw OAuth2Exception::invalidRequest('Redirect URI does not match the registered one');
        }

        // Scope and state allow to perform additional validation
        $scope  = $queryParams['scope'] ?? null;
        $state  = $queryParams['state'] ?? null;
        $scopes = is_string($scope) ? explode(' ', $scope) : [];

        $authorizationCode = $this->authorizationCodeService->createToken($redirectUri, $owner, $client, $scopes);

        $uri = http_build_query(array_filter([
            'code'  => $authorizationCode->getToken(),
            'state' => $state,
        ]));

        return new Response\RedirectResponse($redirectUri . '?' . $uri);
    }

    /**
     * {@inheritdoc}
     *
     * @throws OAuth2Exception
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        ?Client $client = null,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $postParams = $request->getParsedBody();

        $code = $postParams['code'] ?? null;

        if (null === $code) {
            throw OAuth2Exception::invalidRequest('Could not find the authorization code in the request');
        }

        /** @var AuthorizationCode $authorizationCode */
        $authorizationCode = $this->authorizationCodeService->getToken($code);

        if (null === $authorizationCode || $authorizationCode->isExpired()) {
            throw OAuth2Exception::invalidGrant('Authorization code cannot be found or is expired');
        }

        $clientId = $postParams['client_id'] ?? null;

        if ($authorizationCode->getClient()->getId() !== $clientId) {
            throw OAuth2Exception::invalidRequest(
                'Authorization code\'s client does not match with the one that created the authorization code'
            );
        }

        // If owner is null, we reuse the same as the authorization code
        $owner = $owner ?: $authorizationCode->getOwner();

        // Everything is okey, let's start the token generation!
        $scopes = $authorizationCode->getScopes(); // reuse the scopes from the authorization code

        $accessToken = $this->accessTokenService->createToken($owner, $client, $scopes);

        // Before generating a refresh token, we must make sure the authorization server supports this grant
        $refreshToken = null;

        if ($this->authorizationServer->hasGrant(RefreshTokenGrant::GRANT_TYPE)) {
            $refreshToken = $this->refreshTokenService->createToken($owner, $client, $scopes);
        }

        return $this->prepareTokenResponse($accessToken, $refreshToken);
    }

    public function setAuthorizationServer(AuthorizationServerInterface $authorizationServer): void
    {
        $this->authorizationServer = $authorizationServer;
    }

    public function allowPublicClients(): bool
    {
        return true;
    }
}
