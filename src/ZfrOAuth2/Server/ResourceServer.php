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
     * @param TokenService $accessTokenService
     */
    public function __construct(TokenService $accessTokenService)
    {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * Get the access token
     *
     * Note that this method will only match tokens that are not expired and match the given scopes (if any).
     * Otherwise, null will be returned
     *
     * @link   http://tools.ietf.org/html/rfc6750#page-5
     * @param  HttpRequest $request
     * @param  array       $scopes
     * @return AccessToken|null
     */
    public function getAccessToken(HttpRequest $request, $scopes = [])
    {
        if (!$token = $this->extractAccessToken($request)) {
            return null;
        }

        $token = $this->accessTokenService->getToken($token);

        if ($token === null || !$this->isTokenValid($token, $scopes)) {
            return null;
        }

        return $token;
    }

    /**
     * Extract the token either from Authorization header or query params
     *
     * @param  HttpRequest $request
     * @return string|null
     * @throws InvalidAccessTokenException If access token is malformed in the Authorization header
     */
    private function extractAccessToken(HttpRequest $request)
    {
        $headers = $request->getHeaders();

        // The preferred way is using Authorization header
        if ($headers->has('Authorization')) {
            // Header value is expected to be "Bearer xxx"
            $parts = explode(' ', $headers->get('Authorization')->getFieldValue());
            $token = end($parts); // Access token is the last value

            if (count($parts) < 2 || empty($token)) {
                throw new InvalidAccessTokenException('No access token could be found in Authorization header');
            }
        } else {
            $token = $request->getQuery('access_token');
        }

        return $token;
    }

    /**
     * Check if the given token is valid (not expired and/or match the given scopes)
     *
     * @param  AccessToken $accessToken
     * @param  array       $scopes
     * @return bool
     */
    private function isTokenValid(AccessToken $accessToken, $scopes = [])
    {
        if ($accessToken->isExpired()) {
            return false;
        }

        if (!empty($scopes) && !$accessToken->matchScopes($scopes)) {
            return false;
        }

        return true;
    }
}
