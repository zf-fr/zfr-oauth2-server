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
use ZfrOAuth2\Server\Service\AuthorizationCodeService;

/**
 * Implementation of the authorization grant
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationGrant implements GrantInterface
{
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
     * @param AuthorizationCodeService $authorizationCodeService
     */
    public function __construct(AuthorizationCodeService $authorizationCodeService)
    {
        $this->authorizationCodeService = $authorizationCodeService;
    }

    /**
     * {@inheritDoc}
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
     */
    public function createTokenResponse(HttpRequest $request, Client $client)
    {
        // TODO: Implement createResponse() method.
    }

    /**
     * {@inheritDoc}
     */
    public function allowPublicClients()
    {
        return true;
    }
}
