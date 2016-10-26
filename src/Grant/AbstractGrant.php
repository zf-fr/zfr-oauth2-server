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

namespace ZfrOAuth2\Server\Grant;

use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\RefreshToken;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
abstract class AbstractGrant implements GrantInterface
{
    /**
     * {@inheritDoc}
     */
    public function getType(): string
    {
        return static::GRANT_TYPE;
    }

    /**
     * {@inheritDoc}
     */
    public function getResponseType(): string
    {
        return static::GRANT_RESPONSE_TYPE;
    }

    /**
     * Prepare the actual HttpResponse for the token
     *
     * @param  AccessToken       $accessToken
     * @param  RefreshToken|null $refreshToken
     * @param  bool              $useRefreshTokenScopes
     * @return ResponseInterface
     */
    protected function prepareTokenResponse(
        AccessToken $accessToken,
        RefreshToken $refreshToken = null,
        $useRefreshTokenScopes = false
    ) {
        $owner  = $accessToken->getOwner();
        $scopes = $useRefreshTokenScopes ? $refreshToken->getScopes() : $accessToken->getScopes();

        $responseBody = [
            'access_token' => $accessToken->getToken(),
            'token_type'   => 'Bearer',
            'expires_in'   => $accessToken->getExpiresIn(),
            'scope'        => implode(' ', $scopes),
            'owner_id'     => $owner ? $owner->getTokenOwnerId() : null
        ];

        if (null !== $refreshToken) {
            $responseBody['refresh_token'] = $refreshToken->getToken();
        }

        return new Response\JsonResponse(array_filter($responseBody));
    }
}
