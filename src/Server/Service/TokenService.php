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

declare(strict_types=1);

namespace ZfrOAuth2\Server\Service;

use DateTime;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use ZfrOAuth2\Server\Entity\AbstractToken;
use ZfrOAuth2\Server\Exception\OAuth2Exception;

/**
 * Token service
 *
 * You'll need to create one token service per type of token, as the repositories are not the same (as well
 * as the token TTL)
 *
 * @TODO    : should we create one service per token type? I think it's a bit useless, as the only thing that would
 *        be overridden is the token TTL
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class TokenService
{

    const AUTHORIZATION_CODE_SERVICE = 'ZfrOAuth2\Server\Service\AuthorizationCodeService';
    const ACCESS_TOKEN_SERVICE       = 'ZfrOAuth2\Server\Service\AccessTokenService';
    const REFRESH_TOKEN_SERVICE      = 'ZfrOAuth2\Server\Service\RefreshTokenService';

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
    public function createToken(AbstractToken $token):AbstractToken
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
        } while ($this->tokenRepository->find($tokenHash) !== null);

        $token->setToken($tokenHash);

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
        /* @var \ZfrOAuth2\Server\Entity\AbstractToken $tokenFromDb */
        $tokenFromDb = $this->tokenRepository->find($token);

        // Because the collation is most often case insensitive, we need to add a check here to ensure
        // that the token matches case
        if (!$tokenFromDb || !$this->compareStrings($tokenFromDb->getToken(), $token)) {
            return null;
        }

        return $tokenFromDb;
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

    /**
     * This method is extracted from Zend\Crypt (so that we avoid the whole dependency)
     *
     * @param  string $expected
     * @param  string $actual
     * @return bool
     */
    private function compareStrings($expected, $actual)
    {
        $expected = (string) $expected;
        $actual   = (string) $actual;

        if (function_exists('hash_equals')) {
            return hash_equals($expected, $actual);
        }

        $lenExpected = strlen($expected);
        $lenActual   = strlen($actual);
        $len         = min($lenExpected, $lenActual);

        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($expected[$i]) ^ ord($actual[$i]);
        }
        $result |= $lenExpected ^ $lenActual;

        return ($result === 0);
    }
}
