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
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

use function explode;
use function is_string;

/**
 * @licence MIT
 */
class RefreshTokenGrant extends AbstractGrant
{
    public const GRANT_TYPE          = 'refresh_token';
    public const GRANT_RESPONSE_TYPE = '';

    private AccessTokenService $accessTokenService;

    private RefreshTokenService $refreshTokenService;

    private ServerOptions $serverOptions;

    public function __construct(
        AccessTokenService $accessTokenService,
        RefreshTokenService $refreshTokenService,
        ServerOptions $serverOptions
    ) {
        $this->accessTokenService  = $accessTokenService;
        $this->refreshTokenService = $refreshTokenService;
        $this->serverOptions       = $serverOptions;
    }

    /**
     * @throws OAuth2Exception (invalid_request).
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        throw OAuth2Exception::invalidRequest('Refresh token grant does not support authorization');
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

        $refreshToken = $postParams['refresh_token'] ?? null;

        if (null === $refreshToken) {
            throw OAuth2Exception::invalidRequest('Refresh token is missing');
        }

        // We can fetch the actual token, and validate it
        /** @var RefreshToken $refreshToken */
        $refreshToken = $this->refreshTokenService->getToken((string) $refreshToken);

        if (null === $refreshToken || $refreshToken->isExpired()) {
            throw OAuth2Exception::invalidGrant('Refresh token is expired');
        }

        // We can now create a new access token! First, we need to make some checks on the asked scopes,
        // because according to the spec, a refresh token can create an access token with an equal or lesser
        // scope, but not more
        $scope  = $postParams['scope'] ?? null;
        $scopes = is_string($scope) ? explode(' ', $scope) : $refreshToken->getScopes();

        if (! $refreshToken->matchScopes($scopes)) {
            throw OAuth2Exception::invalidScope(
                'The scope of the new access token exceeds the scope(s) of the refresh token'
            );
        }

        $owner       = $refreshToken->getOwner();
        $accessToken = $this->accessTokenService->createToken($owner, $client, $scopes);

        // We may want to revoke the old refresh token
        if ($this->serverOptions->getRotateRefreshTokens()) {
            if ($this->serverOptions->getRevokeRotatedRefreshTokens()) {
                $this->refreshTokenService->deleteToken($refreshToken);
            }

            $refreshToken = $this->refreshTokenService->createToken($owner, $client, $scopes);
        }

        // We can generate the response!
        return $this->prepareTokenResponse($accessToken, $refreshToken, true);
    }

    public function allowPublicClients(): bool
    {
        return true;
    }
}
