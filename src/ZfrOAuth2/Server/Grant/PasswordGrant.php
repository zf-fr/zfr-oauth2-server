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
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * Implementation of the password grant model
 *
 * This authorization grant type, also known as "resource owner password credentials", is ideal
 * when you trust the client (for instance for a native app)
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-4.3
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class PasswordGrant implements GrantInterface, AuthorizationServiceAwareInterface
{
    use AuthorizationServerAwareTrait;

    /**
     * Constants for the password grant
     */
    const GRANT_TYPE          = 'password';
    const GRANT_RESPONSE_TYPE = null;

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
     * Callable that is used to verify the username and password
     *
     * This callable MUST return an object that implement the TokenOwnerInterface, or
     * null if no identity can be matched with the given credentials
     *
     * @var callable
     */
    protected $callback;

    /**
     * @param AccessTokenService  $accessTokenService
     * @param RefreshTokenService $refreshTokenService
     * @param callable            $callback
     */
    public function __construct(
        AccessTokenService $accessTokenService,
        RefreshTokenService $refreshTokenService,
        callable $callback
    ) {
        $this->accessTokenService  = $accessTokenService;
        $this->refreshTokenService = $refreshTokenService;
        $this->callback            = $callback;
    }

    /**
     * {@inheritDoc}
     * @throws OAuth2Exception
     */
    public function createResponse(HttpRequest $request, Client $client = null)
    {
        // Validate the user using its username and password
        $username = $request->getPost('username');
        $password = $request->getPost('password');

        if (null === $username || null == $password) {
            throw OAuth2Exception::invalidRequest('Username and/or password is missing');
        }

        $owner = $this->callback($username, $password);

        if (!$owner instanceof TokenOwnerInterface) {
            throw OAuth2Exception::invalidGrant('Either username or password are incorrect');
        }

        // Everything is okey, we can start tokens generation!
        $accessToken = $this->accessTokenService->createToken($client, $owner);

        $responseBody = [
            'access_token' => $accessToken->getToken(),
            'token_type'   => 'Bearer',
            'expires_in'   => $accessToken->getExpiresIn()
        ];

        // Before generating a refresh token, we must make sure the authorization server supports this grant
        if ($this->authorizationServer->hasGrant(RefreshTokenGrant::GRANT_TYPE)) {
            $refreshToken                  = $this->refreshTokenService->createToken($client, $owner);
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
