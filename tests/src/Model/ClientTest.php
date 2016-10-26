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

namespace ZfrOAuth2Test\Server\Model;

use ZfrOAuth2\Server\Model\Client;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Model\Client
 */
class ClientTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @dataProvider providerGenerateNewClient
     */
    public function testGenerateNewAccessToken($id, $name, $secret, $redirectUris)
    {
        /** @var Client $client */
        $client = Client::createNewClient($name, $redirectUris);

        $this->assertEquals($name, $client->getName());
        $this->assertEmpty($client->getSecret());
        $this->assertTrue(1 === preg_match('/[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}/',
                $client->getId(), $matches));

        if (null !== $redirectUris) {
            if (is_string($redirectUris)) {
                $redirectUris = explode(" ", $redirectUris);
            }
            $this->assertCount(count($redirectUris), $client->getRedirectUris());
        } else {
            $this->assertTrue(is_array($client->getRedirectUris()));
            $this->assertEmpty($client->getRedirectUris());
        }

    }

    public function providerGenerateNewClient()
    {
        return [
            [1, 'name', 'secret', 'http://www.example.com'],
            [1, 'name', null, null],
        ];
    }

    /**
     * @dataProvider providerReconstitute
     */
    public function testReconstitute($data)
    {
        /** @var Client $client */
        $client = Client::reconstitute($data);


        $this->assertEquals($data['id'], $client->getId());

        if (isset($data['name'])) {
            $this->assertSame($data['name'], $client->getName());
        } else {
            $this->assertNull($client->getName());
        }

        if (isset($data['secret'])) {
            $this->assertSame($data['secret'], $client->getSecret());
        } else {
            $this->assertEquals('', $client->getSecret());
        }

        if (isset($data['redirectUris'])) {
            if (is_string($data['redirectUris'])) {
                $data['redirectUris'] = explode(" ", $data['redirectUris']);
            }
            $this->assertCount(count($data['redirectUris']), $client->getRedirectUris());
        } else {
            $this->assertTrue(is_array($client->getRedirectUris()));
            $this->assertEmpty($client->getRedirectUris());
        }
    }

    public function providerReconstitute()
    {
        return [
            [
                [
                    'id'           => '325e4ffc-ff89-4558-971a-6c6a4c13e718',
                    'name'         => 'name',
                    'secret'       => 'secret',
                    'redirectUris' => ['http://www.example.com']
                ],
                [
                    'id'           => '29432c0c-fd08-46bb-a9a5-c55ccaf9ccda',
                    'name'         => 'name',
                    'secret'       => '',
                    'redirectUris' => []
                ],
            ],
        ];
    }

    public function testGetters()
    {
        $client = Client::createNewClient('name', 'http://www.example.com');

        $this->assertEmpty($client->getSecret());
        $this->assertTrue(1 === preg_match('/[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}/',
                $client->getId(), $matches));
        $this->assertEquals('name', $client->getName());
        $this->assertEquals('http://www.example.com', $client->getRedirectUris()[0]);
    }

    public function testCanCheckPublicClient()
    {
        $client = Client::createNewClient('name', 'http://www.example.com');
        $this->assertTrue($client->isPublic());

        $client = Client::createNewClient('name', 'http://www.example.com');

        $client->generateSecret();
        $this->assertFalse($client->isPublic());
    }

    public function testRedirectUri()
    {
        $client = Client::createNewClient('name', 'http://www.example.com');
        $this->assertCount(1, $client->getRedirectUris());
        $this->assertTrue($client->hasRedirectUri('http://www.example.com'));
        $this->assertFalse($client->hasRedirectUri('http://www.example2.com'));

        $client = Client::createNewClient('name', ['http://www.example1.com', 'http://www.example2.com']);
        $this->assertCount(2, $client->getRedirectUris());
        $this->assertTrue($client->hasRedirectUri('http://www.example1.com'));
        $this->assertTrue($client->hasRedirectUri('http://www.example2.com'));
        $this->assertFalse($client->hasRedirectUri('http://www.example3.com'));
    }

    public function testGenerateSecret()
    {
        $client = Client::createNewClient('name');

        $secret = $client->generateSecret();

        $this->assertEquals(60, strlen($client->getSecret()));
        $this->assertEquals(40, strlen($secret));

        $this->assertFalse($client->authenticate('azerty'));
        $this->assertTrue($client->authenticate($secret));
        $this->assertFalse($client->authenticate($client->getSecret()));
    }

    public function testAuthenticate()
    {
        $client = Client::reconstitute(
            [
                'id'           => '325e4ffc-ff89-4558-971a-6c6a4c13e718',
                'name'         => 'name',
                'secret'       => '$2y$10$LHAy5E0b1Fie9NpV6KeOWeAmVdA6UnaXP82TNoMGiVl0Sy/E6PUs6',
                'redirectUris' => []
            ]
        );

        $this->assertFalse($client->authenticate('azerty'));
        $this->assertTrue($client->authenticate('17ef7d94a9172d31c6336424651c861fad9c891e'));
        $this->assertFalse($client->authenticate($client->getSecret()));
    }

}
