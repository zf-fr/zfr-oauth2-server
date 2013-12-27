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
    public function createResponse(HttpRequest $request, Client $client = null)
    {
        // In this mode, we ABSOLUTELY need a client
        if (null === $client) {
            throw OAuth2Exception::invalidClient('Client is invalid');
        }

        // Everything is okey, we can start tokens generation!
        $accessToken = $this->accessTokenService->createToken($client, $owner);

        // We can generate the response!
        $response = new HttpResponse();
        $response->setContent(json_encode([
            'access_token' => $accessToken->getToken(),
            'token_type'   => 'Bearer',
            'expires_in'   => $accessToken->getExpiresIn()
        ]));

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    public function getGrantType()
    {
        return 'client_credentials';
    }

    /**
     * {@inheritDoc}
     */
    public function getResponseType()
    {
        return null;
    }
}
