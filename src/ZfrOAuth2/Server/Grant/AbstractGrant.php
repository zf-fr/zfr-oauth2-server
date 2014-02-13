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

namespace ZfrOAuth2\Server\Grant;

use ZfrOAuth2\Server\Entity\AbstractToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
abstract class AbstractGrant implements GrantInterface
{
    /**
     * Populate a token
     *
     * The actual token (sensitive part) is generated in the token service
     *
     * @param  AbstractToken            $token
     * @param  Client|null              $client
     * @param  TokenOwnerInterface|null $owner
     * @param  array|string             $scopes
     * @return void
     */
    protected function populateToken(
        AbstractToken $token,
        Client $client = null,
        TokenOwnerInterface $owner = null,
        $scopes = []
    ) {
        if (null !== $client) {
            $token->setClient($client);
        }

        if (null !== $owner) {
            $token->setOwner($owner);
        }

        $token->setScopes($scopes ?: []);
    }

    /**
     * {@inheritDoc}
     */
    public function getType()
    {
        return static::GRANT_TYPE;
    }

    /**
     * {@inheritDoc}
     */
    public function getResponseType()
    {
        return static::GRANT_RESPONSE_TYPE;
    }
}
