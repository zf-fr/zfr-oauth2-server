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

/**
 * Authorization code model
 *
 * An authorization code is a special token that acts as an intermediary between the client and
 * the resource owner. An authorization code can then be exchanged against an access token
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationCode extends AbstractToken
{
    /**
     * @var string
     */
    private $redirectUri;

    /**
     * Create a new AuthorizationCode
     *
     * @param int                          $ttl
     * @param TokenOwnerInterface|null     $owner
     * @param Client|null                  $client
     * @param string|string[]|Scope[]|null $scopes
     * @param string                       $redirectUri
     */
    public static function createNewAuthorizationCode(
        int $ttl,
        string $redirectUri = null,
        TokenOwnerInterface $owner = null,
        Client $client = null,
        $scopes = null
    ): AuthorizationCode {
        $token = static::createNew($ttl, $owner, $client, $scopes);

        $token->redirectUri = $redirectUri ?? '';

        return $token;
    }

    /**
     * @param array $data
     * @return AuthorizationCode
     */
    public static function reconstitute(array $data): self
    {
        $token = parent::reconstitute($data);

        $token->redirectUri = $data['redirectUri'];

        return $token;
    }

    /**
     * @return string
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }
}
