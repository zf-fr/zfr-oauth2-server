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
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class RefreshTokenGrant extends AbstractGrant
{
    const GRANT_TYPE          = 'refresh_token';
    const GRANT_RESPONSE_TYPE = null;

    /**
     * @var TokenService
     */
    protected $accessTokenService;

    /**
     * @var TokenService
     */
    protected $refreshTokenService;

    /**
     * @var bool
     */
    protected $rotateRefreshTokens = false;

    /**
     * @param TokenService $accessTokenService
     * @param TokenService $refreshTokenService
     */
    public function __construct(TokenService $accessTokenService, TokenService $refreshTokenService)
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
    public function createAuthorizationResponse(HttpRequest $request, Client $client, TokenOwnerInterface $owner = null)
    {
        throw OAuth2Exception::invalidRequest('Refresh token grant does not support authorization');
    }

    /**
     * {@inheritDoc}
     */
    public function createTokenResponse(HttpRequest $request, Client $client = null, TokenOwnerInterface $owner = null)
    {
        if (!$refreshToken = $request->getPost('refresh_token')) {
            throw OAuth2Exception::invalidRequest('Refresh token is missing');
        }

        // We can fetch the actual token, and validate it
        $refreshToken = $this->refreshTokenService->getToken($refreshToken);

        if (null === $refreshToken || $refreshToken->isExpired()) {
            throw OAuth2Exception::invalidGrant('Refresh token is expired');
        }

        // We can now create a new access token! First, we need to make some checks on the asked scopes,
        // because according to the spec, a refresh token can create an access token with an equal or lesser
        // scope, but not more
        $scopes = $request->getPost('scope') ?: $refreshToken->getScopes();

        if (!$refreshToken->matchScopes($scopes)) {
            throw OAuth2Exception::invalidScope(
                'The scope of the new access token exceeds the scope(s) of the refresh token'
            );
        }

        $owner       = $refreshToken->getOwner();
        $accessToken = new AccessToken();

        $this->populateToken($accessToken, $client, $owner, $scopes);
        $accessToken = $this->accessTokenService->createToken($accessToken);

        // We may want to revoke the old refresh token
        if ($this->rotateRefreshTokens) {
            $this->refreshTokenService->deleteToken($refreshToken);

            $refreshToken = new RefreshToken();

            $this->populateToken($refreshToken, $client, $owner, $scopes);
            $refreshToken = $this->refreshTokenService->createToken($refreshToken);
        }

        // We can generate the response!
        $response     = new HttpResponse();
        $responseBody = [
            'access_token'  => $accessToken->getToken(),
            'token_type'    => 'Bearer',
            'expires_in'    => $accessToken->getExpiresIn(),
            'refresh_token' => $refreshToken->getToken(),
            'scope'         => implode(' ', $refreshToken->getScopes()),
            'owner_id'      => $owner ? $owner->getTokenOwnerId() : null
        ];

        $response->setContent(json_encode(array_filter($responseBody)));

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
