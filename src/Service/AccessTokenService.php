<?php

declare(strict_types=1);

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

namespace ZfrOAuth2\Server\Service;

use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\Scope;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Repository\AccessTokenRepositoryInterface;

/**
 * AccessTokenService
 *
 * @licence MIT
 */
class AccessTokenService extends AbstractTokenService
{
    /** @var AccessTokenRepositoryInterface */
    protected $tokenRepository;

    /**
     * Create a new token (and generate the token)
     *
     * @param TokenOwnerInterface $owner
     * @param Client              $client
     * @param string[]|Scope[]    $scopes
     * @throws OAuth2Exception
     */
    public function createToken($owner, $client, array $scopes = []): AccessToken
    {
        if (empty($scopes)) {
            $scopes = $this->scopeService->getDefaultScopes();
        }

        $this->validateTokenScopes($scopes, $client);

        do {
            $token = AccessToken::createNewAccessToken(
                $this->serverOptions->getAccessTokenTtl(),
                $owner,
                $client,
                $scopes
            );
        } while ($this->tokenRepository->tokenExists($token->getToken()));

        return $this->tokenRepository->save($token);
    }
}
