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

namespace ZfrOAuth2\Server\Entity;

use DateTime;

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
    protected $token;

    /**
     * @var Client
     */
    protected $client;

    /**
     * @var TokenOwnerInterface
     */
    protected $owner;

    /**
     * @var DateTime
     */
    protected $expiresAt;

    /**
     * @var array
     */
    protected $scopes = [];

    /**
     * Set the token (either access or refresh token)
     *
     * @param  string $token
     * @return void
     */
    public function setToken($token)
    {
        $this->token = (string) $token;
    }

    /**
     * Get the token
     *
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Set the client that issued this token
     *
     * @param  Client $client
     * @return void
     */
    public function setClient(Client $client)
    {
        $this->client = $client;
    }

    /**
     * Get the client that issued this token
     *
     * @return Client
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Set the token owner
     *
     * @param  TokenOwnerInterface $owner
     * @return void
     */
    public function setOwner(TokenOwnerInterface $owner)
    {
        $this->owner = $owner;
    }

    /**
     * Get the token owner
     *
     * @return TokenOwnerInterface
     */
    public function getOwner()
    {
        return $this->owner;
    }

    /**
     * Set when this token should expire
     *
     * @param  DateTime $expiresAt
     * @return void
     */
    public function setExpiresAt(DateTime $expiresAt)
    {
        $this->expiresAt = clone $expiresAt;
    }

    /**
     * Get when this token should expire
     *
     * @return DateTime
     */
    public function getExpiresAt()
    {
        return clone $this->expiresAt;
    }

    /**
     * Compute in how many seconds does the token expire (if expired, will return a negative value)
     *
     * @return int
     */
    public function getExpiresIn()
    {
        return $this->expiresAt->getTimestamp() - (new DateTime('now'))->getTimestamp();
    }

    /**
     * Is the token expired?
     *
     * @return bool
     */
    public function isExpired()
    {
        return $this->expiresAt < new DateTime('now');
    }

    /**
     * Set the scopes of this token
     *
     * @param  array|string|Scope[] $scopes
     * @return void
     */
    public function setScopes($scopes)
    {
        if (is_string($scopes)) {
            $scopes = explode(' ', $scopes);
        } else {
            foreach ($scopes as &$scope) {
                $scope = $scope instanceof Scope ? $scope->getName() : (string) $scope;
            }
        }

        $this->scopes = $scopes;
    }

    /**
     * Get the scopes
     *
     * @return array
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Match the scopes of the token with the one provided in the parameter
     *
     * @param  array|string $scopes
     * @return bool
     */
    public function matchScopes($scopes)
    {
        $scopes = is_string($scopes) ? explode(' ', $scopes) : $scopes;
        $diff   = array_diff($scopes, $this->scopes);

        return empty($diff);
    }
}
