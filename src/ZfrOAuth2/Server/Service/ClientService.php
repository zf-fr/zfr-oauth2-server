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

namespace ZfrOAuth2\Server\Service;

use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use Zend\Crypt\Password\Bcrypt;
use Zend\Math\Rand;
use ZfrOAuth2\Server\Entity\Client;

/**
 * Client service
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ClientService
{
    /**
     * @var ObjectManager
     */
    protected $objectManager;

    /**
     * @var ObjectRepository
     */
    protected $clientRepository;

    /**
     * @var Bcrypt
     */
    protected $bcrypt;

    /**
     * @param ObjectManager    $objectManager
     * @param ObjectRepository $clientRepository
     */
    public function __construct(ObjectManager $objectManager, ObjectRepository $clientRepository)
    {
        $this->objectManager    = $objectManager;
        $this->clientRepository = $clientRepository;
        $this->bcrypt           = new Bcrypt(['cost' => 10]);
    }

    /**
     * Register a new client and generate a strong secret
     *
     * Please note that the secret must be really kept secret, as it is used for some grant type to
     * authorize the client. It is returned as a result of this method, as it's already encrypted
     * in the client object
     *
     * @param  Client $client
     * @return array
     */
    public function registerClient(Client $client)
    {
        // Finally, we must generate a strong, unique secret, and crypt it before storing it
        $secret = Rand::getString(40);
        $client->setSecret($this->bcrypt->create($secret));

        $this->objectManager->persist($client);
        $this->objectManager->flush();

        return [$client, $secret];
    }

    /**
     * Update an existing client
     *
     * @param  Client $client
     * @return Client
     */
    public function updateClient(Client $client)
    {
        $this->objectManager->flush($client);

        return $client;
    }

    /**
     * Get the client using its id
     *
     * @param  string $id
     * @return Client|null
     */
    public function getClient($id)
    {
        return $this->clientRepository->find($id);
    }

    /**
     * Authenticate the client
     *
     * @param  Client $client
     * @param  string $secret
     * @return bool True if properly authenticated, false otherwise
     */
    public function authenticate(Client $client, $secret)
    {
        return $this->bcrypt->verify($secret, $client->getSecret());
    }
}
