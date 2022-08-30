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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Service\AccessTokenService;

use function explode;
use function is_string;

/**
 * Implementation of the client credentials grant
 *
 * This is the most easy grant. It can creates an access token only by authenticating the client
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-4.4
 *
 * @licence MIT
 */
class ClientCredentialsGrant extends AbstractGrant
{
    public const GRANT_TYPE          = 'client_credentials';
    public const GRANT_RESPONSE_TYPE = '';

    /**
     * Access token service (used to create access token)
     */
    private AccessTokenService $accessTokenService;

    public function __construct(AccessTokenService $accessTokenService)
    {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * @throws OAuth2Exception (invalid_request).
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        throw OAuth2Exception::invalidRequest('Client credentials grant does not support authorization');
    }

    /**
     * {@inheritdoc}
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        ?Client $client = null,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $postParams = $request->getParsedBody();

        // Everything is okey, we can start tokens generation!
        $scope  = $postParams['scope'] ?? null;
        $scopes = is_string($scope) ? explode(' ', $scope) : [];

        /** @var AccessToken $accessToken */
        $accessToken = $this->accessTokenService->createToken($owner, $client, $scopes);

        return $this->prepareTokenResponse($accessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function allowPublicClients(): bool
    {
        return false;
    }
}
