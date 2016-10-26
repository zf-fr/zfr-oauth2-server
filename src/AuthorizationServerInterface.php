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

namespace ZfrOAuth2\Server;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;

/**
 * The authorization server main role is to create access tokens or refresh tokens
 */
interface AuthorizationServerInterface
{
    /**
     * Check if the authorization server supports this grant
     *
     * @param  string $grant
     * @return bool
     */
    public function hasGrant(string $grant): bool;

    /**
     * Check if the authorization server supports this response type
     *
     * @param  string $responseType
     * @return bool
     */
    public function hasResponseType(string $responseType): bool;

    /**
     * @param  ServerRequestInterface   $request
     * @param  TokenOwnerInterface|null $owner
     * @return ResponseInterface
     * @throws OAuth2Exception If no "response_type" could be found in the GET parameters
     */
    public function handleAuthorizationRequest(
        ServerRequestInterface $request,
        TokenOwnerInterface $owner = null
    ):ResponseInterface;

    /**
     * @param  ServerRequestInterface   $request
     * @param  TokenOwnerInterface|null $owner
     * @return ResponseInterface
     * @throws OAuth2Exception If no "grant_type" could be found in the POST parameters
     */
    public function handleTokenRequest(
        ServerRequestInterface $request,
        TokenOwnerInterface $owner = null
    ):ResponseInterface;

    /**
     * @param  ServerRequestInterface $request
     * @return ResponseInterface
     * @throws OAuth2Exception If no "token" is present
     */
    public function handleRevocationRequest(ServerRequestInterface $request): ResponseInterface;
}
