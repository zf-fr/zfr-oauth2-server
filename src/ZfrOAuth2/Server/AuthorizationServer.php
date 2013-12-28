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

namespace ZfrOAuth2\Server;

use Zend\Http\Request as HttpRequest;
use Zend\Http\Response as HttpResponse;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Grant\GrantInterface;

/**
 * The authorization server main role is to create access tokens or refresh tokens
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationServer
{
    /**
     * A list of grant interfaces
     *
     * @var GrantInterface[]
     */
    protected $grants = [];

    /**
     * @param GrantInterface[] $grants
     */
    public function __construct(array $grants)
    {
        $this->grants = $grants;
    }

    /**
     * Handle the request
     *
     * @param  HttpRequest $request
     * @return HttpResponse
     * @throws OAuth2Exception If no grant type could be found
     */
    public function handleRequest(HttpRequest $request)
    {
        try {
            $grantType = $request->getPost('grant_type');

            if (null === $grantType) {
                throw OAuth2Exception::invalidRequest('No grant type was found in the request');
            }

            $grant = $this->getGrant($grantType);

            $this->validateClient($request, $grant->allowPublicClients());

            $response = $grant->createResponse($request);
        } catch(OAuth2Exception $exception) {
            return $this->createResponseFromOAuthException($exception);
        }

        // According to the spec, we should set those headers (http://tools.ietf.org/html/rfc6749#section-5.1)
        $response->getHeaders()->addHeaderLine('Cache-Control', 'no-store')
                               ->addHeaderLine('Pragma', 'no-cache');

        return $response;
    }

    /**
     * Validate the client
     *
     * @param  HttpRequest $request
     * @param  bool        $optionalSecret
     * @throws Exception\OAuth2Exception
     */
    public function validateClient(HttpRequest $request, $optionalSecret = false)
    {
        // We first try to get the Authorization header, as this is the recommended way according to the spec
        if ($header = $request->getHeader('Authorization')) {
            // The value is "Basic xxx", we are interested in the last part
            $parts = explode(' ', $header->getFieldValue());
            $value = base64_decode(end($parts));

            list($id, $secret) = explode(':', $value);
        } else {
            $id     = $request->getPost('client_id');
            $secret = $request->getPost('client_secret');
        }

        if (!$optionalSecret && !$secret) {
            throw OAuth2Exception::invalidClient('Client secret is missing');
        }

        $client = $this->clientService->getClient($id, $secret);

        if (null === $client) {
            throw OAuth2Exception::invalidClient('Client cannot be found');
        }

        // @TODO: validate grant type
    }

    /**
     * Get the grant by its name
     *
     * @param  string $grantType
     * @return GrantInterface
     * @throws OAuth2Exception If grant type is not registered by this authorization server
     */
    private function getGrant($grantType)
    {
        foreach ($this->grants as $grant) {
            if ($grantType === $grant->getGrantType()) {
                return $grant;
            }
        }

        // If we reach here... then no grant was found. Not good!
        throw OAuth2Exception::unsupportedGrantType(sprintf(
            'Grant type "%s" is not supported by this server',
            $grantType
        ));
    }

    /**
     * Create a response from the exception, using the format of the spec
     *
     * @link   http://tools.ietf.org/html/rfc6749#section-5.2
     * @param  OAuth2Exception $exception
     * @return HttpResponse
     */
    private function createResponseFromOAuthException(OAuth2Exception $exception)
    {
        $response = new HttpResponse();
        $response->setStatusCode(400);

        $body = ['error' => $exception->getCode(), 'error_description' => $exception->getMessage()];
        $response->setContent(json_encode($body));

        return $response;
    }
}
