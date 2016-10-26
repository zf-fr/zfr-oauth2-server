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

namespace ZfrOAuth2\Server\Model;

use DateTime;
use DateTimeInterface;

/**
 * Provide basic functionality for both access tokens, refresh tokens and authorization codes
 *
 * Please note that scopes are stored as a saved as a string instead using associations to scope entities, mainly
 * for performance reasons and to avoid useless database calls
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
abstract class AbstractToken
{
    /**
     * @var string
     */
    private $token;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var TokenOwnerInterface
     */
    private $owner;

    /**
     * @var DateTimeInterface
     */
    protected $expiresAt;

    /**
     * @var array
     */
    private $scopes = [];

    /**
     * AbstractToken constructor.
     */
    private function __construct()
    {
    }

    /**
     * Create a new AbstractToken
     *
     * @param int                          $ttl
     * @param TokenOwnerInterface|null     $owner
     * @param Client|null                  $client
     * @param string|string[]|Scope[]|null $scopes
     * @return static
     */
    protected static function createNew(
        int $ttl,
        TokenOwnerInterface $owner = null,
        Client $client = null,
        $scopes = null
    ): self {
        if (isset($scopes) && $scopes instanceof Scope) {
            $scopes = $scopes->getName();
        }

        if (is_string($scopes)) {
            $scopes = explode(' ', $scopes);
        }

        if (is_array($scopes)) {
            foreach ($scopes as &$scope) {
                $scope = $scope instanceof Scope ? $scope->getName() : (string) $scope;
            }
        }

        $token = new static();

        $token->token     = bin2hex(random_bytes(20));
        $token->owner     = $owner;
        $token->client    = $client;
        $token->scopes    = $scopes ?? [];
        $token->expiresAt = $ttl ? (new DateTime())->modify("+$ttl seconds") : null;

        return $token;
    }

    /**
     * @param array $data
     * @return static
     */
    public static function reconstitute(array $data)
    {
        $token = new static();

        $token->token     = $data['token'];
        $token->expiresAt = $data['expiresAt'];
        $token->owner     = $data['owner'];
        $token->client    = $data['client'];
        $token->scopes    = (array) $data['scopes'];

        return $token;
    }

    /**
     * Get the token
     *
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Get the client that issued this token
     *
     * @return Client|null
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Get the token owner
     *
     * @return TokenOwnerInterface|null
     */
    public function getOwner()
    {
        return $this->owner;
    }

    /**
     * Get when this token should expire
     *
     * @return DateTimeInterface|null
     */
    public function getExpiresAt()
    {
        return $this->expiresAt ? clone $this->expiresAt : null;
    }

    /**
     * Compute in how many seconds does the token expire (if expired, will return a negative value)
     *
     * @return int
     */
    public function getExpiresIn(): int
    {
        return $this->expiresAt->getTimestamp() - (new DateTime('now'))->getTimestamp();
    }

    /**
     * Is the token expired?
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        return $this->expiresAt < new DateTime('now');
    }

    /**
     * Get the scopes
     *
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Match the scopes of the token with the one provided in the parameter
     *
     * @param  array|string $scopes
     * @return bool
     */
    public function matchScopes($scopes): bool
    {
        $scopes = is_string($scopes) ? explode(' ', $scopes) : $scopes;
        $diff   = array_diff($scopes, $this->scopes);

        return empty($diff);
    }

    /**
     * Check if the token is valid, according to the given scope(s) and expiration dates
     *
     * @param  array|string $scopes
     * @return bool
     */
    public function isValid($scopes): bool
    {
        if ($this->isExpired()) {
            return false;
        }

        if (!empty($scopes) && !$this->matchScopes($scopes)) {
            return false;
        }

        return true;
    }
}
