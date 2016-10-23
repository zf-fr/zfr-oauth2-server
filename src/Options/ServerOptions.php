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

namespace ZfrOAuth2\Server\Options;

use Assert\Assertion;

/**
 * Options class
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
final class ServerOptions
{
    /**
     * Authorization code TTL
     *
     * @var int
     */
    private $authorizationCodeTtl = 120;

    /**
     * Access token TTL
     *
     * @var int
     */
    private $accessTokenTtl = 3600;

    /**
     * Refresh token TTL
     *
     * @var int
     */
    private $refreshTokenTtl = 86400;

    /**
     * Rotate refresh tokens (for RefreshTokenGrant)
     *
     * @var bool
     */
    private $rotateRefreshTokens = false;

    /**
     * Revoke rotated refresh tokens (for RefreshTokenGrant)
     *
     * @var bool
     */
    private $revokeRotatedRefreshTokens = true;

    /**
     * Set the owner callable
     *
     * @var callable|string
     */
    private $ownerCallable;

    /**
     * Grants that the authorization server must support
     *
     * @var array
     */
    private $grants = [];

    /**
     * Constructor
     *
     * @param  array $options
     */
    private function __construct(array $options)
    {
        if (isset($options['authorization_code_ttl'])) {
            Assertion::nullOrInteger($options['authorization_code_ttl']);
        }

        if (isset($options['access_token_ttl'])) {
            Assertion::nullOrInteger($options['access_token_ttl']);
        }

        if (isset($options['refresh_token_ttl'])) {
            Assertion::nullOrInteger($options['refresh_token_ttl']);
        }

        if (isset($options['rotate_refresh_tokens'])) {
            Assertion::nullOrBoolean($options['rotate_refresh_tokens']);
        }

        if (isset($options['revoke_rotated_refresh_tokens'])) {
            Assertion::nullOrBoolean($options['revoke_rotated_refresh_tokens']);
        }

        if (isset($options['owner_callable'])) {
            if (!is_string($options['owner_callable'])) {
                Assertion::nullOrIsCallable($options['owner_callable']);
            }
        }

        if (isset($options['grants'])) {
            Assertion::nullOrIsArray($options['grants']);
        }

        $this->authorizationCodeTtl      = $options['authorization_code_ttl'] ?? 120;
        $this->accessTokenTtl            = $options['access_token_ttl'] ?? 3600;
        $this->refreshTokenTtl           = $options['refresh_token_ttl'] ?? 86400;
        $this->rotateRefreshTokens       = $options['rotate_refresh_tokens'] ?? false;
        $this->revokeRotatedRefreshToken = $options['revoke_rotated_refresh_tokens'] ?? true;
        $this->ownerCallable             = $options['owner_callable'] ?? null;
        $this->grants                    = $options['grants'] ?? [];
    }

    /**
     * Set one or more configuration properties
     *
     * @param  array $options
     * @return static
     */
    public static function fromArray(array $options = []): self
    {
        return new self($options);
    }

    /**
     * Get the authorization code TTL
     *
     * @return int
     */
    public function getAuthorizationCodeTtl(): int
    {
        return $this->authorizationCodeTtl;
    }

    /**
     * Get the access token TTL
     *
     * @return int
     */
    public function getAccessTokenTtl(): int
    {
        return $this->accessTokenTtl;
    }

    /**
     * Get the refresh token TTL
     *
     * @return int
     */
    public function getRefreshTokenTtl(): int
    {
        return $this->refreshTokenTtl;
    }

    /**
     * Get the rotate refresh token option while refreshing an access token
     *
     * @return boolean
     */
    public function getRotateRefreshTokens(): bool
    {
        return $this->rotateRefreshTokens;
    }

    /**
     * Get the revoke rotated refresh token option while refreshing an access token
     *
     * @return bool
     */
    public function getRevokeRotatedRefreshTokens(): bool
    {
        return $this->revokeRotatedRefreshTokens;
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
     * Get the grants the authorization server must support
     *
     * @return array
     */
    public function getGrants(): array
    {
        return $this->grants;
    }
}
