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

use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Scope;

/**
 * The resource server main role is to validate the access token and that its scope covers the
 * requested resource
 *
 * Currently, the resource server only implements the Bearer token usage, as described in the
 * RFC 6750 (http://tools.ietf.org/html/rfc6750)
 */
interface ResourceServerInterface
{
    /**
     * Get the access token
     *
     * @param  ServerRequestInterface $request
     * @param  array|string|Scope[]   $scopes
     * @return AccessToken|null
     * @throws Exception\InvalidAccessTokenException If given access token is invalid or expired
     */
    public function getAccessToken(ServerRequestInterface $request, $scopes = []);
}
