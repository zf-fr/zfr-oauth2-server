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

namespace ZfrOAuth2\Server\Service;

use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Repository\ClientRepositoryInterface;

/**
 * Client service
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ClientService
{

    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * ClientService constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     */
    public function __construct(ClientRepositoryInterface $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }

    /**
     * Register a new client and generate a strong secret
     *
     * Please note that the secret must be really kept secret, as it is used for some grant type to
     * authorize the client. It is returned as a result of this method, as it's already encrypted
     * in the client object
     *
     * @param string $name
     * @param array  $redirectUris
     * @return array [$client, $secret]
     */
    public function registerClient(string $name, array $redirectUris): array
    {
        do {
            $client = Client::createNewClient($name, $redirectUris);
        } while ($this->clientRepository->idExists($client->getId()));

        $secret = $client->generateSecret();
        $client = $this->clientRepository->save($client);

        return [$client, $secret];
    }

    /**
     * Get the client using its id
     *
     * @param  string $id
     * @return Client|null
     */
    public function getClient(string $id)
    {
        return $this->clientRepository->findById($id);
    }
}
