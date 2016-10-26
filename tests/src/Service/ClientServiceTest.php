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

namespace ZfrOAuth2Test\Server\Service;

use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Repository\ClientRepositoryInterface;
use ZfrOAuth2\Server\Service\ClientService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Service\ClientService
 */
class ClientServiceTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var ClientRepositoryInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $clientRepository;

    /**
     * @var ClientService
     */
    protected $clientService;

    public function setUp()
    {
        $this->clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $this->clientService    = new ClientService($this->clientRepository);
    }

    public function testCanGetClient()
    {
        $client = Client::reconstitute([
                'id'           => 'client_id',
                'name'         => 'name',
                'secret'       => '',
                'redirectUris' => [],
            ]
        );

        $this->clientRepository->expects($this->once())
                               ->method('findById')
                               ->with('client_id')
                               ->will($this->returnValue($client));

        $this->assertSame($client, $this->clientService->getClient('client_id'));
    }

    public function testRegisterClient()
    {
        $this->clientRepository->expects($this->once())
                            ->method('idExists')
                            ->willReturn(false);

        $this->clientRepository->expects($this->once())
            ->method('save')
            ->will($this->returnArgument(0));

        list($client, $secret) = $this->clientService->registerClient('name', ['http://www.example.com']);

        $this->assertEquals(60, strlen($client->getSecret()));
        $this->assertEquals(40, strlen($secret));
    }
}
