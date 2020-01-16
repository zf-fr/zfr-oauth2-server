<?php

declare(strict_types=1);

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

namespace ZfrOAuth2\Server\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Diactoros\Response\JsonResponse;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;
use ZfrOAuth2\Server\ResourceServerInterface;

/**
 * Middleware for a resource server
 *
 * This middleware aims to sit very early in your pipeline. It will check if a request has an access token, and if so,
 * will try to validate it. If the token is invalid, the middleware will immediately return.
 *
 * If the token is valid, it will store it as part of the request under the attribute "oauth_token", so that it can
 * be used later one by a permission system, for instance
 */
class ResourceServerMiddleware implements MiddlewareInterface
{
    /**
     * @var ResourceServerInterface
     */
    private $resourceServer;

    /**
     * @var string
     */
    private $tokenRequestAttribute;

    /**
     * @param ResourceServerInterface $resourceServer
     */
    public function __construct(ResourceServerInterface $resourceServer, string $tokenRequestAttribute = 'oauth_token')
    {
        $this->resourceServer = $resourceServer;
        $this->tokenRequestAttribute = $tokenRequestAttribute;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $token = $this->resourceServer->getAccessToken($request);
        } catch (InvalidAccessTokenException $exception) {
            // If we're here, this means that there was an access token, but it's either expired or invalid. If
            // that's the case we must immediately return
            return new JsonResponse(['error' => $exception->getCode(), 'error_description' => $exception->getMessage()],
                401);
        }

        // Otherwise, if we actually have a token and set it as part of the request attribute for next step
        return $handler->handle($request->withAttribute($this->tokenRequestAttribute, $token));
    }
}
