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

namespace ZfrOAuth2\Server\Model;

use Ramsey\Uuid\Uuid;

/**
 * Client model
 *
 * A client is typically an application (either a third-party or your own application) that integrates with the
 * provider (in this case, you are the provider)
 *
 * There are two types of clients: the public and confidential ones. Some grants absolutely require a client,
 * while other don't need it. The reason is that for public clients (like a JavaScript application), the secret
 * cannot be kept... well... secret! To create a public client, you just need to let an empty secret. More
 * info about that: http://tools.ietf.org/html/rfc6749#section-2.1
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class Client
{
    /**
     * @var string
     */
    private $id = '';

    /**
     * @var string
     */
    private $name = '';

    /**
     * @var string
     */
    private $secret = '';

    /**
     * @var array
     */
    private $redirectUris = [];

    /**
     * Client constructor.
     */
    private function __construct()
    {
    }

    /**
     * Create a new Client
     *
     * @param string               $name         Clients name
     * @param string|string[]|null $redirectUris Client allowed redirect direct url's
     * @return Client
     */
    public static function createNewClient(string $name, $redirectUris = null)
    {
        if (isset($redirectUris) && is_string($redirectUris)) {
            $redirectUris = explode(' ', $redirectUris);
        }

        if (isset($redirectUris) && is_array($redirectUris)) {
            foreach ($redirectUris as &$redirectUri) {
                $redirectUri = trim((string) $redirectUri);
            }
        }

        $client = new static();

        $client->id           = (string) Uuid::uuid4();
        $client->name         = $name;
        $client->redirectUris = $redirectUris ?? [];

        return $client;
    }

    /**
     * @param array $data
     * @return Client
     */
    public static function reconstitute(array $data): Client
    {
        $client = new static();

        $client->id           = $data['id'];
        $client->name         = $data['name'];
        $client->secret       = $data['secret'];
        $client->redirectUris = $data['redirectUris'];

        return $client;
    }

    /**
     * Get the client id
     *
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }


    /**
     * Get the client name
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get the client secret
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Get the redirect URIs
     *
     * @return array
     */
    public function getRedirectUris(): array
    {
        return $this->redirectUris;
    }

    /**
     * Check if the given redirect URI is in the list
     *
     * @param  string $redirectUri
     * @return bool
     */
    public function hasRedirectUri(string $redirectUri): bool
    {
        return in_array($redirectUri, $this->redirectUris, true);
    }

    /**
     * Is this client a public client?
     *
     * @return bool
     */
    public function isPublic(): bool
    {
        return empty($this->secret);
    }

    /**
     * Authenticate the client
     *
     * @param  string $secret
     * @return bool True if properly authenticated, false otherwise
     */
    public function authenticate(string $secret): bool
    {
        return password_verify($secret, $this->getSecret());
    }

    /**
     * Creates a strong, unique secret and crypt it on the model
     *
     * @return string Secret not encrypted
     */
    public function generateSecret()
    {
        $secret       = bin2hex(random_bytes(20));
        $this->secret = password_hash($secret, PASSWORD_DEFAULT);

        return $secret;
    }
}
