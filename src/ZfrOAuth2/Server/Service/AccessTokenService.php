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
use Doctrine\Common\Persistence\ObjectManager;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

/**
 * Service that allows to perform various operation on access tokens
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AccessTokenService
{
    /**
     * @var ObjectManager
     */
    protected $objectManager;

    /**
     * Default access token
     *
     * @var int
     */
    protected $defaultAccessTokenTTL = 3600;

    /**
     * @param ObjectManager $objectManager
     */
    public function __construct(ObjectManager $objectManager)
    {
        $this->objectManager = $objectManager;
    }

    /**
     * Set the default access token ttl
     *
     * @param  int $ttl
     * @return void
     */
    public function setDefaultAccessTokenTTL($ttl)
    {
        $this->defaultAccessTokenTTL = (int) $ttl;
    }

    /**
     * Create a new access token
     *
     * @param  Client              $client
     * @param  TokenOwnerInterface $owner
     * @param  DateTime            $expiresAt
     * @param  string              $scope
     * @return AccessToken
     */
    public function createToken(Client $client, TokenOwnerInterface $owner, DateTime $expiresAt = null, $scope = '')
    {
        if (null === $expiresAt) {
            $expiresAt = new DateTime();
            $expiresAt->setTimestamp(time() + $this->defaultAccessTokenTTL);
        }

        $accessToken = new AccessToken();
        $accessToken->setClient($client);
        $accessToken->setOwner($owner);
        $accessToken->setExpiresAt($expiresAt);
        $accessToken->setScope($scope);

        // Persist the token
        $this->objectManager->persist($accessToken);
        $this->objectManager->flush();
    }
}
