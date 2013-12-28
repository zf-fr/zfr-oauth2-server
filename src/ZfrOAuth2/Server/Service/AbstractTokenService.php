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
use Doctrine\Common\Collections\Criteria;
use Doctrine\Common\Collections\Selectable;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use ZfrOAuth2\Server\Entity\AbstractToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Exception\RuntimeException;

/**
 * Abstract token service
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
abstract class AbstractTokenService
{
    /**
     * @var ObjectManager
     */
    protected $objectManager;

    /**
     * @var ObjectRepository
     */
    protected $tokenRepository;

    /**
     * Token TTL (in seconds)
     *
     * @var int
     */
    protected $tokenTTL = 0;

    /**
     * @param ObjectManager    $objectManager
     * @param ObjectRepository $tokenRepository
     */
    public function __construct(ObjectManager $objectManager, ObjectRepository $tokenRepository)
    {
        $this->objectManager   = $objectManager;
        $this->tokenRepository = $tokenRepository;
    }

    /**
     * Set the token TTL for this service
     *
     * @param  int $tokenTTL
     * @return void
     */
    public function setTokenTTL($tokenTTL)
    {
        $this->tokenTTL = (int) $tokenTTL;
    }

    /**
     * Get the token TTL for this service
     *
     * @return int
     */
    public function getTokenTTL()
    {
        return $this->tokenTTL;
    }

    /**
     * Get a token using its identifier (the token itself)
     *
     * @param  string $token
     * @return AbstractToken|null
     */
    public function getToken($token)
    {
        return $this->tokenRepository->find($token);
    }

    /**
     * Remove the abstract token from the underlying storage
     *
     * @param  AbstractToken $token
     * @return void
     */
    public function deleteToken(AbstractToken $token)
    {
        $this->objectManager->remove($token);
        $this->objectManager->flush();
    }

    /**
     * Delete all the expired tokens
     *
     * This can be executed as a CRON task to clean a database. Because we are type hinting on ObjectManager,
     * we cannot take advantage of optimized delete queries. This method also only works with Selectable
     *
     * @return void
     * @throws RuntimeException
     */
    public function deleteExpiredTokens()
    {
        if (!$this->tokenRepository instanceof Selectable) {
            throw new RuntimeException('Deleting expired tokens currently only work with Selectable repositories');
        }

        $criteria = Criteria::create(Criteria::expr()->lt('expiresAt', new DateTime()));
        $criteria->setMaxResults(50);

        do {
            $expiredTokens = $this->tokenRepository->matching($criteria);

            foreach ($expiredTokens as $expiredToken) {
                $this->tokenRepository->remove($expiredToken);
            }

            $this->tokenRepository->flush();
        } while (count($expiredTokens) > 0);
    }

    /**
     * @param Client $client
     * @param $scope
     */
    public function validateScope(Client $client, $scope)
    {

    }

    /**
     * Generate a unique key for the token
     *
     * @return string
     */
    protected function generateKey()
    {
        // @TODO which algorithm to use?
        return 'abc';
    }
}
