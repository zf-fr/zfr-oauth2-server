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
use Zend\Math\Rand;
use ZfrOAuth2\Server\Entity\AbstractToken;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Exception\RuntimeException;

/**
 * Token service
 *
 * You'll need to create one token service per type of token, as the repositories are not the same (as well
 * as the token TTL)
 *
 * @TODO: should we create one service per token type? I think it's a bit useless, as the only thing that would
 *        be overridden is the token TTL
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class TokenService
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
     * @var ScopeService
     */
    protected $scopeService;

    /**
     * Token TTL (in seconds)
     *
     * @var int
     */
    protected $tokenTTL = 3600;

    /**
     * @param ObjectManager    $objectManager
     * @param ObjectRepository $tokenRepository
     * @param ScopeService     $scopeService
     */
    public function __construct(
        ObjectManager $objectManager,
        ObjectRepository $tokenRepository,
        ScopeService $scopeService
    ) {
        $this->objectManager   = $objectManager;
        $this->tokenRepository = $tokenRepository;
        $this->scopeService    = $scopeService;
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
     * Create a new token (and generate the token)
     *
     * @param  AbstractToken $token
     * @return AbstractToken
     */
    public function createToken(AbstractToken $token)
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
        $token->setToken(Rand::getString(40));

        $this->objectManager->persist($token);
        $this->objectManager->flush();

        return $token;
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

        $criteria = new Criteria(Criteria::expr()->lt('expiresAt', new DateTime()));
        $criteria->setMaxResults(50);

        do {
            $expiredTokens = $this->tokenRepository->matching($criteria);

            foreach ($expiredTokens as $expiredToken) {
                $this->objectManager->remove($expiredToken);
            }

            $this->objectManager->flush();
        } while (count($expiredTokens) > 0);
    }

    /**
     * Validate the token scopes against the registered scope
     *
     * @param  array $scopes
     * @return void
     * @throws OAuth2Exception
     */
    protected function validateTokenScopes(array $scopes)
    {
        $registeredScopes = $this->scopeService->getAll();

        foreach ($registeredScopes as &$registeredScope) {
            $registeredScope = $registeredScope->getName();
        }

        $diff = array_diff($scopes, $registeredScopes);

        if (count($diff) > 0) {
            throw OAuth2Exception::invalidScope(sprintf(
                'Some scope(s) do not exist: %s',
                implode(', ', $diff)
            ));
        }
    }
}
