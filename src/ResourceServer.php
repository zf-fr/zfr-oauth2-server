<?php

declare(strict_types = 1);

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

use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Service\AccessTokenService;

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
class ResourceServer implements ResourceServerInterface
{
    /**
     * @var AccessTokenService
     */
    private $accessTokenService;

    /**
     * @param AccessTokenService $accessTokenService
     */
    public function __construct(AccessTokenService $accessTokenService)
    {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * Get the access token
     *
     * Note that this method will only match tokens that are not expired and match the given scopes (if any).
     * If no token is pass, this method will return null, but if a token is given does not exist (ie. has been
     * deleted) or is not valid, then it will trigger an exception
     *
     * @link   http://tools.ietf.org/html/rfc6750#page-5
     * @param  ServerRequestInterface $request
     * @param  array                  $scopes
     * @return AccessToken|null
     * @throws InvalidAccessTokenException If given access token is invalid or expired
     */
    public function getAccessToken(ServerRequestInterface $request, $scopes = [])
    {
        if (!$token = $this->extractAccessToken($request)) {
            return null;
        }

        $token = $this->accessTokenService->getToken($token);

        if ($token === null || !$token->isValid($scopes)) {
            throw new InvalidAccessTokenException('Access token has expired or has been deleted');
        }

        return $token;
    }

    /**
     * Extract the token either from Authorization header or query params
     *
     * @param  ServerRequestInterface $request
     * @return string|null
     */
    private function extractAccessToken(ServerRequestInterface $request)
    {
        // The preferred way is using Authorization header
        if ($request->hasHeader('Authorization')) {
            // Header value is expected to be "Bearer xxx"
            $parts = explode(' ', $request->getHeaderLine('Authorization'));

            if (count($parts) < 2) {
                return null;
            }

            return end($parts);
        }

        // Default back to authorization in query param
        $queryParams = $request->getQueryParams();

        return $queryParams['access_token'] ?? null;
    }
}
