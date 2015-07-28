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

namespace ZfrOAuth2\Server\Event;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\EventManager\Event;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

/**
 * Event that is triggered whenever an access token has been created or failed. You have access to both
 * the request and response, as well as the optional token owner.
 *
 * If you want to alter the response before sending it back to the client, you can do it by fetching the current
 * response, alter it and store it again
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class TokenEvent extends Event
{
    const EVENT_TOKEN_CREATED = 'token.created';
    const EVENT_TOKEN_FAILED  = 'token.failed';

    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * @var ResponseInterface
     */
    protected $response;

    /**
     * @var TokenOwnerInterface
     */
    private $tokenOwner;

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @param TokenOwnerInterface    $tokenOwner
     */
    public function __construct(
        ServerRequestInterface $request,
        ResponseInterface $response,
        TokenOwnerInterface $tokenOwner = null
    ) {
        $this->request    = $request;
        $this->response   = $response;
        $this->tokenOwner = $tokenOwner;
    }

    /**
     * @return ServerRequestInterface
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @param  ResponseInterface $response
     * @return void
     */
    public function setResponse(ResponseInterface $response)
    {
        $this->response = $response;
    }

    /**
     * @return ResponseInterface
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * @return TokenOwnerInterface
     */
    public function getTokenOwner()
    {
        return $this->tokenOwner;
    }
}
