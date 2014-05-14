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

use Zend\EventManager\Event;
use Zend\Http\Request as HttpRequest;
use Zend\Http\Response as HttpResponse;
use ZfrOAuth2\Server\Entity\AccessToken;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class TokenEvent extends Event
{
    const EVENT_TOKEN_CREATED = 'token.created';
    const EVENT_TOKEN_FAILED  = 'token.failed';

    /**
     * @var HttpRequest
     */
    protected $request;

    /**
     * @var array
     */
    protected $responseBody;

    /**
     * @var AccessToken|null
     */
    protected $accessToken;

    /**
     * @param HttpRequest      $request
     * @param array            $responseBody
     * @param AccessToken|null $accessToken
     */
    public function __construct(HttpRequest $request, array $responseBody, AccessToken $accessToken = null)
    {
        $this->request      = $request;
        $this->responseBody = $responseBody;
        $this->accessToken  = $accessToken;
    }

    /**
     * @return HttpRequest
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @param  array $responseBody
     * @return void
     */
    public function setResponseBody(array $responseBody)
    {
        $this->responseBody = $responseBody;
    }

    /**
     * @return array
     */
    public function getResponseBody()
    {
        return $this->responseBody;
    }

    /**
     * @return AccessToken|null
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }
}
