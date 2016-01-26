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

namespace ZfrOAuth2\Server\Options;

/**
 * Options class
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ServerOptions
{
    /**
     * Object manager key
     *
     * @var string
     */
    protected $objectManager = '';

    /**
     * Authorization code TTL
     *
     * @var int
     */
    protected $authorizationCodeTtl = 120;

    /**
     * Access token TTL
     *
     * @var int
     */
    protected $accessTokenTtl = 3600;

    /**
     * Refresh token TTL
     *
     * @var int
     */
    protected $refreshTokenTtl = 86400;

    /**
     * Set the owner callable
     *
     * @var callable|string
     */
    protected $ownerCallable;

    /**
     * Grants that the authorization server must support
     *
     * @var array
     */
    protected $grants = [];

    /**
     * Constructor
     *
     * @param  array|null $options
     */
    public function __construct($options = null)
    {
        if (null !== $options) {
            $this->setFromArray($options);
        }
    }

    /**
     * Set one or more configuration properties
     *
     * @param  array $options
     */
    public function setFromArray(array $options)
    {
        foreach ($options as $key => $value) {
            $setter = 'set' . str_replace('_', '', $key);
            $this->{$setter}($value);
        }
    }

    /**
     * Set the object manager key
     *
     * @param string $objectManager
     */
    public function setObjectManager($objectManager)
    {
        $this->objectManager = (string) $objectManager;
    }

    /**
     * Get the object manager key
     *
     * @return string
     */
    public function getObjectManager():string
    {
        return $this->objectManager;
    }

    /**
     * Set the authorization code TTL
     *
     * @param int $authorizationCodeTtl
     */
    public function setAuthorizationCodeTtl($authorizationCodeTtl)
    {
        $this->authorizationCodeTtl = (int) $authorizationCodeTtl;
    }

    /**
     * Get the authorization code TTL
     *
     * @return int
     */
    public function getAuthorizationCodeTtl():int
    {
        return $this->authorizationCodeTtl;
    }

    /**
     * Set the access token TTL
     *
     * @param int $accessTokenTtl
     */
    public function setAccessTokenTtl($accessTokenTtl)
    {
        $this->accessTokenTtl = (int) $accessTokenTtl;
    }

    /**
     * Get the access token TTL
     *
     * @return int
     */
    public function getAccessTokenTtl():int
    {
        return $this->accessTokenTtl;
    }

    /**
     * Set the refresh token TTL
     *
     * @param int $refreshTokenTtl
     */
    public function setRefreshTokenTtl($refreshTokenTtl)
    {
        $this->refreshTokenTtl = (int) $refreshTokenTtl;
    }

    /**
     * Get the refresh token TTL
     *
     * @return int
     */
    public function getRefreshTokenTtl():int
    {
        return $this->refreshTokenTtl;
    }

    /**
     * Set the callable used to validate a user (or service name)
     *
     * @param callable|string $ownerCallable
     */
    public function setOwnerCallable($ownerCallable)
    {
        $this->ownerCallable = $ownerCallable;
    }

    /**
     * Get the callable used to validate a user
     *
     * @return callable|string
     */
    public function getOwnerCallable()
    {
        return $this->ownerCallable;
    }

    /**
     * Set the grants the authorization server must support
     *
     * @param array $grants
     */
    public function setGrants(array $grants)
    {
        $this->grants = $grants;
    }

    /**
     * Get the grants the authorization server must support
     *
     * @return array
     */
    public function getGrants():array
    {
        return $this->grants;
    }
}
