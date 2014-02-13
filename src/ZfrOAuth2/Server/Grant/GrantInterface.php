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

use Zend\Http\Request;
use Zend\Http\Response;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

/**
 * Interface that all authorization grant type should implement
 *
 * Please note that the grants DOES NOT authenticate the client. This is done in the authorization
 * server. You must therefore make sure that the grants are only called from the authorization server
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-1.3
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
interface GrantInterface
{
    /**
     * Constants that need to be overridden for each grant
     */
    const GRANT_TYPE          = null;
    const GRANT_RESPONSE_TYPE = null;

    /**
     * Create an authorization response (this is the response to the "authorization endpoint"))
     *
     * @param  Request                  $request
     * @param  Client                   $client
     * @param  TokenOwnerInterface|null $owner
     * @return Response
     */
    public function createAuthorizationResponse(Request $request, Client $client, TokenOwnerInterface $owner = null);

    /**
     * Create a token response according (this is the response to the "token endpoint")
     *
     * @param  Request                  $request
     * @param  Client|null              $client
     * @param  TokenOwnerInterface|null $owner
     * @return Response
     */
    public function createTokenResponse(Request $request, Client $client = null, TokenOwnerInterface $owner = null);

    /**
     * Get the grant type
     *
     * @return string
     */
    public function getType();

    /**
     * Get the grant response type
     *
     * @return string|null
     */
    public function getResponseType();

    /**
     * Does this authorization grant allow public clients?
     *
     * @return bool
     */
    public function allowPublicClients();
}
