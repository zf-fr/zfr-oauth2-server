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
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

/**
 * Service that allows to perform various operation on refresh tokens
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class RefreshTokenService extends AbstractTokenService
{
    /**
     * Token TTL (in seconds) for the refresh tokens
     *
     * @var int
     */
    protected $tokenTTL = 604800;

    /**
     * Create a new refresh token
     *
     * @param  Client              $client
     * @param  TokenOwnerInterface $owner
     * @param  string              $scope
     * @return RefreshToken
     */
    public function createToken(Client $client, TokenOwnerInterface $owner, $scope = '')
    {
        $expiresAt = new DateTime();
        $expiresAt->setTimestamp(time() + $this->defaultTokenTTL);

        $refreshToken = new RefreshToken();
        $refreshToken->setClient($client);
        $refreshToken->setOwner($owner);
        $refreshToken->setExpiresAt($expiresAt);
        $refreshToken->setScope($scope);

        // Persist the token
        $this->objectManager->persist($refreshToken);
        $this->objectManager->flush();

        return $refreshToken;
    }
}
