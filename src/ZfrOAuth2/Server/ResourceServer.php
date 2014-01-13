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

namespace ZfrOAuth2\Server;

use Zend\Http\Request as HttpRequest;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * The resource server main role is to validate the access token and that its scope covers the
 * requested resource
 *
 * Currently, the resource server only implements the Bearer token usage, as described in the
 * RFC 6750 (http://tools.ietf.org/html/rfc6750)
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ResourceServer
{
    /**
     * @var TokenService
     */
    protected $accessTokenService;

    /**
     * @var AccessToken
     */
    protected $accessToken;

    /**
     * @param TokenService $accessTokenService
     */
    public function __construct(TokenService $accessTokenService)
    {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * Check if the request is valid
     *
     * If the scope parameter is given, it will also check that the token has enough permissions
     *
     * @param  HttpRequest  $request
     * @param  array|string $scopes
     * @return bool
     */
    public function isRequestValid(HttpRequest $request, $scopes = [])
    {
        // We extract the token and get the actual instance from storage
        $accessToken = $this->getAccessToken($request);

        // It must exist and must not be outdated, otherwise it's wrong!
        if (null === $accessToken || $accessToken->isExpired()) {
            return false;
        }

        if (!empty($scopes) && !$accessToken->matchScopes($scopes)) {
            return false;
        }

        return true;
    }

    /**
     * Extract the access token from the Authorization header of the request
     *
     * @param  HttpRequest $request
     * @return AccessToken
     * @throws InvalidAccessTokenException If no access token could be found
     */
    public function getAccessToken(HttpRequest $request)
    {
        // Try to get it from memory cache first
        if (null !== $this->accessToken) {
            return $this->accessToken;
        }

        $headers = $request->getHeaders();

        if (!$headers->has('Authorization')) {
            return null;
        }

        // Header value is expected to be "Bearer xxx"
        $parts = explode(' ', $headers->get('Authorization')->getFieldValue());
        $token = end($parts); // Access token is the last value

        if (count($parts) < 2 || empty($token)) {
            throw new InvalidAccessTokenException('No access token could be found in Authorization header');
        }

        $this->accessToken = $this->accessTokenService->getToken($token);

        return $this->accessToken;
    }
}
