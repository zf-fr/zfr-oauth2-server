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
    public function testGetters()
    {
        $client = new Client('id', 'name', 'secret', ['http://www.example.com']);

        $this->assertEquals('id', $client->getId());
        $this->assertEquals('secret', $client->getSecret());
        $this->assertEquals('name', $client->getName());
        $this->assertEquals('http://www.example.com', $client->getRedirectUris()[0]);
    }

    public function testCanCheckPublicClient()
    {
        $client = new Client('id', 'name', null, ['http://www.example.com']);
        $this->assertTrue($client->isPublic());

        $client = new Client('id', 'name', 'secret', ['http://www.example.com']);
        $this->assertFalse($client->isPublic());
    }

    public function testRedirectUri()
    {
        $client = new Client('id', 'name', null, ['http://www.example.com']);
        $this->assertCount(1, $client->getRedirectUris());
        $this->assertTrue($client->hasRedirectUri('http://www.example.com'));
        $this->assertFalse($client->hasRedirectUri('http://www.example2.com'));

        $client = new Client('id', 'name', null, ['http://www.example1.com', 'http://www.example2.com']);
        $this->assertCount(2, $client->getRedirectUris());
        $this->assertTrue($client->hasRedirectUri('http://www.example1.com'));
        $this->assertTrue($client->hasRedirectUri('http://www.example2.com'));
        $this->assertFalse($client->hasRedirectUri('http://www.example3.com'));
    }

    public function testGenerateSecret()
    {
        $client = new Client('client_id', 'name');

        $secret = $client->generateSecret();

        $this->assertEquals(60, strlen($client->getSecret()));
        $this->assertEquals(40, strlen($secret));

        $this->assertFalse($client->authenticate('azerty'));
        $this->assertTrue($client->authenticate($secret));
        $this->assertFalse($client->authenticate($client->getSecret()));
    }

    public function testAuthenticate()
    {
        $client = new Client('client_id', 'name', '$2y$10$LHAy5E0b1Fie9NpV6KeOWeAmVdA6UnaXP82TNoMGiVl0Sy/E6PUs6');

        $this->assertFalse($client->authenticate('azerty'));
        $this->assertTrue($client->authenticate('17ef7d94a9172d31c6336424651c861fad9c891e'));
        $this->assertFalse($client->authenticate($client->getSecret()));
    }

}
