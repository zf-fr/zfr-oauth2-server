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

declare(strict_types = 1);

namespace ZfrOAuth2\Server;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Zend\Stratigility\MiddlewarePipe;

/**
 * Middleware for handling the authorization logic
 *
 * This middleware currently create three URLs, based on the OAuth specification:
 *
 *      - /oauth/authorize: NOT IMPLEMENTED YET
 *      - /oauth/token: generate an access token
 *      - /oauth/revoke: revoke an existing token
 */
class AuthorizationServerMiddleware extends MiddlewarePipe
{
    /**
     * @var AuthorizationServerInterface
     */
    private $authorizationServer;

    /**
     * @param AuthorizationServerInterface $authorizationServer
     */
    public function __construct(AuthorizationServerInterface $authorizationServer)
    {
        parent::__construct();

        $this->authorizationServer = $authorizationServer;

        $this->pipe('/authorize', [$this, 'handleAuthorizeRequest']);
        $this->pipe('/token', [$this, 'handleTokenRequest']);
        $this->pipe('/revoke', [$this, 'handleRevocationRequest']);
    }

    /**
     * @param Request       $request
     * @param Response      $response
     * @param callable|null $next
     */
    public function handleAuthorizeRequest(
        Request $request,
        Response $response,
        callable $next = null
    ):ResponseInterface {
        throw new \RuntimeException('Not implemented yet');
    }

    /**
     * Generate a new access token for the given request
     *
     * @param  Request       $request
     * @param  Response      $response
     * @param  callable|null $next
     * @return Response
     */
    public function handleTokenRequest(Request $request, Response $response, callable $next = null):ResponseInterface
    {
        // @TODO: we should integrate with an authentication service to pass the logged user, if any. Currently,
        // it will work out of the box for password grant

        return $this->authorizationServer->handleTokenRequest($request);
    }

    /**
     * Revoke a given token
     *
     * @param  Request       $request
     * @param  Response      $response
     * @param  callable|null $next
     * @return Response
     */
    public function handleRevocationRequest(
        Request $request,
        Response $response,
        callable $next = null
    ):ResponseInterface {
        return $this->authorizationServer->handleRevocationRequest($request);
    }
}
