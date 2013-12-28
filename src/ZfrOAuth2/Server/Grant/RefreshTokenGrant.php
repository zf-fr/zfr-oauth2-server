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
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class RefreshTokenGrant implements GrantInterface
{
    /**
     * Constants for the refresh token grant
     */
    const GRANT_TYPE          = 'refresh_token';
    const GRANT_RESPONSE_TYPE = null;

    /**
     * @var AccessTokenService
     */
    protected $accessTokenService;

    /**
     * @var RefreshTokenService
     */
    protected $refreshTokenService;

    /**
     * @var bool
     */
    protected $rotateRefreshTokens = false;

    /**
     * @param AccessTokenService  $accessTokenService
     * @param RefreshTokenService $refreshTokenService
     */
    public function __construct(AccessTokenService $accessTokenService, RefreshTokenService $refreshTokenService)
    {
        $this->accessTokenService  = $accessTokenService;
        $this->refreshTokenService = $refreshTokenService;
    }

    /**
     * Set if we should rotate refresh tokens
     *
     * If set to true, then a new refresh token will be created each time an access token is asked from it,
     * and the old refresh token is deleted
     *
     * @param  bool $rotateTokens
     * @return void
     */
    public function setRotateRefreshTokens($rotateTokens)
    {
        $this->rotateRefreshTokens = (bool) $rotateTokens;
    }

    /**
     * {@inheritDoc}
     */
    public function createAuthorizationResponse(HttpRequest $request, Client $client)
    {
        throw OAuth2Exception::invalidRequest('Refresh token grant does not support authorization');
    }

    /**
     * {@inheritDoc}
     */
    public function createTokenResponse(HttpRequest $request, Client $client)
    {
        if (!$refreshToken = $request->getPost('refresh_token')) {
            throw OAuth2Exception::invalidRequest('Refresh token is missing');
        }

        // We can fetch the actual token, and validate it
        $refreshToken = $this->refreshTokenService->getToken($refreshToken);
        if ($refreshToken->isExpired()) {
            throw OAuth2Exception::invalidRequest('Refresh token is expired');
        }

        // Okey, we can create a new access token!
        $scope       = $request->getPost('scope');
        $accessToken = $this->accessTokenService->createToken($client, $refreshToken->getOwner(), $scope);

        // We may want to revoke the old refresh token
        if ($this->rotateRefreshTokens) {
            $owner = $refreshToken->getOwner();

            $this->refreshTokenService->deleteToken($refreshToken);
            $refreshToken = $this->refreshTokenService->createToken($client, $owner);
        }

        // We can generate the response!
        $response = new HttpResponse();
        $response->setContent(json_encode([
            'access_token'  => $accessToken->getToken(),
            'token_type'    => 'Bearer',
            'expires_in'    => $accessToken->getExpiresIn(),
            'refresh_token' => $refreshToken->getToken()
        ]));

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
