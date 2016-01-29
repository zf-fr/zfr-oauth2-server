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

namespace ZfrOAuth2\Server\Service;

use DateTime;
use ZfrOAuth2\Server\AccessTokenRepositoryInterface;
use ZfrOAuth2\Server\Model\AbstractToken;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Repository\TokenRepositoryInterface;

/**
 * AuthorizationCodeService
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationCodeService extends TokenService
{
    /**
     * Create a new token (and generate the token)
     *
     * @param  AbstractToken $token
     * @return AbstractToken
     */
    public function createToken(AbstractToken $token): AbstractToken
    {
        $scopes = $token->getScopes();

        if (empty($scopes)) {
            $defaultScopes = $this->scopeService->getDefaultScopes();
            $token->setScopes($defaultScopes);
        } else {
            $this->validateTokenScopes($scopes);
        }

        $expiresAt = new DateTime();
        $expiresAt->setTimestamp(time() + $this->tokenTTL);

        $token->setExpiresAt($expiresAt);

        do {
            $tokenHash = bin2hex(random_bytes(20));
        } while ($this->tokenRepository->findByToken($tokenHash) !== null);

        $token->setToken($tokenHash);

        return $this->tokenRepository->save($token);
    }
}
