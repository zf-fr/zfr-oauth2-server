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

namespace ZfrOAuth2\Server\Model;

use DateTime;
use DateTimeImmutable;

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
    protected $client;

    /**
     * @var TokenOwnerInterface
     */
    protected $owner;

    /**
     * @var DateTimeImmutable
     */
    protected $expiresAt;

    /**
     * @var array
     */
    protected $scopes = [];


    protected function __construct(string $token, TokenOwnerInterface $owner = null, Client $client = null, $scopes = null, DateTimeImmutable $expiresAt = null)
    {
        $this->token     = $token;
        $this->expiresAt = $expiresAt ?? null;
        $this->owner     = $owner ?? null;
        $this->client    = $client ?? null;

        if (is_array($scopes)) {
            foreach ($scopes as &$scope) {
                $scope = $scope instanceof Scope ? $scope->getName() : (string) $scope;
            }
        }

        if (is_string($scopes)) {
            $scopes = explode(' ', $scopes);
        }

        $this->scopes    = $scopes ?? [];
    }

    public static function createToken(int $ttl = 0, TokenOwnerInterface $owner = null, Client $client = null, $scopes = null)
    {
        $token     = bin2hex(random_bytes(20));
        $expiresAt = $ttl ? (new DateTimeImmutable())->modify("+$ttl seconds") : null;

        $class = get_called_class();

        return new $class($token, $owner, $client, $scopes, $expiresAt);
    }

    public static function hydrateToken(string $token, TokenOwnerInterface $owner = null, Client $client = null, $scopes = null, DateTimeImmutable $expiresAt = null)
    {
        $class = get_called_class();

        return new $class($token, $owner, $client, $scopes, $expiresAt);
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
     * @return DateTimeImmutable|null
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
