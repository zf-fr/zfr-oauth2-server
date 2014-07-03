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

use Zend\Http\Response as HttpResponse;
use ZfrOAuth2\Server\Entity\AbstractToken;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
abstract class AbstractGrant implements GrantInterface
{
    /**
     * Populate a token
     *
     * The actual token (sensitive part) is generated in the token service
     *
     * @param  AbstractToken            $token
     * @param  Client|null              $client
     * @param  TokenOwnerInterface|null $owner
     * @param  array|string             $scopes
     * @return void
     */
    protected function populateToken(
        AbstractToken $token,
        Client $client = null,
        TokenOwnerInterface $owner = null,
        $scopes = []
    ) {
        if (null !== $client) {
            $token->setClient($client);
        }

        if (null !== $owner) {
            $token->setOwner($owner);
        }

        $token->setScopes($scopes ?: []);
    }

    /**
     * Prepare the actual HttpResponse for the token
     *
     * @param  AccessToken       $accessToken
     * @param  RefreshToken|null $refreshToken
     * @param  bool              $useRefreshTokenScopes
     * @return HttpResponse
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

        $response = new HttpResponse();

        // Set the access token in metadata so it can be retrieved for events
        $response->setMetadata('accessToken', $accessToken);
        $response->setContent(json_encode(array_filter($responseBody)));

        return $response;
    }
}
