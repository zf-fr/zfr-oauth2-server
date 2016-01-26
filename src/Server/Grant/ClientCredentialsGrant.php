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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * Implementation of the client credentials grant
 *
 * This is the most easy grant. It can creates an access token only by authenticating the client
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-4.4
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ClientCredentialsGrant extends AbstractGrant
{
    const GRANT_TYPE          = 'client_credentials';
    const GRANT_RESPONSE_TYPE = '';

    /**
     * Access token service (used to create access token)
     *
     * @var TokenService
     */
    protected $accessTokenService;

    /**
     * @param TokenService $accessTokenService
     */
    public function __construct(TokenService $accessTokenService)
    {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * {@inheritDoc}
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        TokenOwnerInterface $owner = null
    ) {
        throw OAuth2Exception::invalidRequest('Client credentials grant does not support authorization');
    }

    /**
     * {@inheritDoc}
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        Client $client = null,
        TokenOwnerInterface $owner = null
    ):ResponseInterface {
        $postParams = $request->getParsedBody();

        // Everything is okey, we can start tokens generation!
        $scope       = isset($postParams['scope']) ? $postParams['scope'] : null;
        $accessToken = new AccessToken();

        $this->populateToken($accessToken, $client, $owner, $scope);
        $accessToken = $this->accessTokenService->createToken($accessToken);

        return $this->prepareTokenResponse($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function allowPublicClients():bool
    {
        return false;
    }
}
