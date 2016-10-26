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

namespace ZfrOAuth2\Server\Service;

use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\AbstractToken;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Repository\TokenRepositoryInterface;

/**
 * Token service
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
abstract class AbstractTokenService
{
    /**
     * @var TokenRepositoryInterface
     */
    protected $tokenRepository;

    /**
     * @var ScopeService
     */
    protected $scopeService;

    /**
     * @var ServerOptions
     */
    protected $serverOptions;

    /**
     * @param TokenRepositoryInterface $tokenRepository
     * @param ScopeService             $scopeService
     * @param ServerOptions            $serverOptions
     */
    public function __construct(
        TokenRepositoryInterface $tokenRepository,
        ScopeService $scopeService,
        ServerOptions $serverOptions
    ) {
        $this->tokenRepository = $tokenRepository;
        $this->scopeService    = $scopeService;
        $this->serverOptions   = $serverOptions;
    }

    /**
     * Get a token using its identifier (the token itself)
     *
     * @param  string $token
     * @return AbstractToken|null
     */
    public function getToken(string $token)
    {
        /* @var \ZfrOAuth2\Server\Model\AbstractToken $tokenFromDb */
        $tokenFromDb = $this->tokenRepository->findByToken($token);

        // Because the collation is most often case insensitive, we need to add a check here to ensure
        // that the token matches case
        if (!$tokenFromDb || !hash_equals($tokenFromDb->getToken(), $token)) {
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
        $this->tokenRepository->deleteToken($token);
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
            $registeredScope = is_string($registeredScope) ? $registeredScope : $registeredScope->getName();
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
