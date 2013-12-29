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
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Service\AccessTokenService;

/**
 * Implementation of the client credentials grant
 *
 * This is the most easy grant. It can creates an access token only by authenticating the client
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-4.4
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ClientCredentialsGrant implements GrantInterface
{
    /**
     * Constants for the client credentials grant
     */
    const GRANT_TYPE          = 'client_credentials';
    const GRANT_RESPONSE_TYPE = null;

    /**
     * Access token service (used to create access token)
     *
     * @var AccessTokenService
     */
    protected $accessTokenService;

    /**
     * @param AccessTokenService $accessTokenService
     */
    public function __construct(AccessTokenService $accessTokenService)
    {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * {@inheritDoc}
     */
    public function createAuthorizationResponse(HttpRequest $request, Client $client, TokenOwnerInterface $owner = null)
    {
        throw OAuth2Exception::invalidRequest('Client credentials grant does not support authorization');
    }

    /**
     * {@inheritDoc}
     */
    public function createTokenResponse(HttpRequest $request, Client $client, TokenOwnerInterface $owner = null)
    {
        // Everything is okey, we can start tokens generation!
        // Note that in this grant, the owner of the token is the client itself!
        $accessToken = $this->accessTokenService->createToken($client, $owner, $request->getPost('scope'));

        // We can generate the response!
        $response     = new HttpResponse();
        $responseBody = [
            'access_token' => $accessToken->getToken(),
            'token_type'   => 'Bearer',
            'expires_in'   => $accessToken->getExpiresIn(),
            'scope'        => $accessToken->getScope()
        ];

        $response->setContent(json_encode(array_filter($responseBody)));

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    public function allowPublicClients()
    {
        return false;
    }
}
