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

use Doctrine\Common\Persistence\ManagerRegistry;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;

return [
    'dependencies' => [
        'factories' => [
            /**
             * Utils
             */
            ManagerRegistry::class => My\ManagerRegistryFactory::class,
        ]
    ],

    /**
     * Use this config if you are using Doctrine 2 ORM. Otherwise, you can delete it
     */
    'doctrine'     => [
        /**
         * Set the resolver. You should change the value to your user class (or any class that
         * implements the ZfrOAuth2/Server/Entity/TokenOwnerInterface interface
         */
        'entity_resolver' => [
            'orm_default' => [
                'resolvers' => [
                    TokenOwnerInterface::class => My\Entity\Authentication\User::class
                ],
            ],
        ],
    ],

    'zfr_oauth2_server' => [
        /**
         * Doctrine object manager key
         */
        'object_manager' => 'orm_default',

        /**
         * Various tokens TTL
         */
        // 'authorization_code_ttl' => 120,
        // 'access_token_ttl'       => 3600,
        // 'refresh_token_ttl'      => 86400,

        /**
         * Registered grants for this server
         */
        'grants'         => [],

        /**
         * A callable used to validate the username and password when using the
         * password grant
         */
        // 'owner_callable' => null,
    ]
];
