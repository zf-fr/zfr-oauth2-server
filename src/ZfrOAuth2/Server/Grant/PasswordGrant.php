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

use Zend\Http\Request as HttpRequest;
use Zend\Http\Response as HttpResponse;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Service\ClientService;

/**
 * Implementation of the password grant model
 *
 * This authorization grant type, also known as "resource owner password credentials", is ideal
 * when you trust the client (for instance for a native app)
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-4.3
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class PasswordGrant extends AbstractGrant
{
    /**
     * Callable that is used to verify the username and password
     *
     * @var callable
     */
    protected $callback;

    /**
     * @param ClientService $clientService
     * @param callable      $callback
     */
    public function __construct(ClientService $clientService, callable $callback)
    {
        parent::__construct($clientService);
        $this->callback = $callback;
    }

    /**
     * Validate the request according to the current grant
     *
     * @param  HttpRequest $request
     * @return HttpResponse
     */
    public function createResponse(HttpRequest $request)
    {
        $this->validateGrantType($request);
        $this->validateClient($request);

        // Validate the user using its username and password
        $username = $request->getPost('username');
        $password = $request->getPost('password');

        if (null === $username || null == $password) {
            throw OAuth2Exception::invalidRequest('Username and/or password is missing');
        }

        if (!$this->callback($username, $password)) {
            throw OAuth2Exception::invalidGrant('Either username or password are incorrect');
        }

        // Everything is okey, we can start access token generation!
    }

    /**
     * {@inheritDoc}
     */
    public function getGrantType()
    {
        return 'password';
    }

    /**
     * {@inheritDoc}
     */
    public function getResponseType()
    {
        return null;
    }
}
