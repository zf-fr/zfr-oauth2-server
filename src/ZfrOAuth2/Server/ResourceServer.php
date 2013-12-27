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
class ResourceServer
{
    /**
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
     * Check if the request is valid
     *
     * @param  HttpRequest $request
     * @return bool
     */
    public function isRequestValid(HttpRequest $request)
    {
        $accessToken = $this->extractAccessToken($request);

        if (null === $accessToken) {
            return false;
        }

        // We can get the actual instance from storage
        $accessToken = $this->accessTokenService->getToken($accessToken);

        // It must exist and must not be outdated, otherwise it's wrong!
        if (null === $accessToken || $accessToken->isExpired()) {
            return false;
        }

        // We must check that the client scope match the ones of the access token

        return true;
    }

    /**
     * Extract the access token from the Authorization header of the request
     *
     * @param  HttpRequest $request
     * @return string|null
     */
    private function extractAccessToken(HttpRequest $request)
    {
        // Header value is expected to be "Bearer xxx"
        $parts = explode(' ', $request->getHeader('Authorization')->getFieldValue());

        if (count($parts) < 2) {
            return null;
        }

        return end($parts);
    }
}
