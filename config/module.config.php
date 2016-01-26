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

use Doctrine\ORM\Mapping\Driver\XmlDriver;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\AuthorizationServerMiddleware;
use ZfrOAuth2\Server\Container\AccessTokenServiceFactory;
use ZfrOAuth2\Server\Container\AuthorizationCodeServiceFactory;
use ZfrOAuth2\Server\Container\AuthorizationGrantFactory;
use ZfrOAuth2\Server\Container\AuthorizationServerFactory;
use ZfrOAuth2\Server\Container\AuthorizationServerMiddlewareFactory;
use ZfrOAuth2\Server\Container\ClientCredentialsGrantFactory;
use ZfrOAuth2\Server\Container\ClientServiceFactory;
use ZfrOAuth2\Server\Container\PasswordGrantFactory;
use ZfrOAuth2\Server\Container\RefreshTokenGrantFactory;
use ZfrOAuth2\Server\Container\RefreshTokenServiceFactory;
use ZfrOAuth2\Server\Container\ResourceServerFactory;
use ZfrOAuth2\Server\Container\ResourceServerMiddlewareFactory;
use ZfrOAuth2\Server\Container\ScopeServiceFactory;
use ZfrOAuth2\Server\Container\ServerOptionsFactory;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\ResourceServer;
use ZfrOAuth2\Server\ResourceServerMiddleware;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\ScopeService;
use ZfrOAuth2\Server\Service\TokenService;

return [
    'dependencies' => [
        'factories' => [
            /**
             * Middleware
             */
            AuthorizationServerMiddleware::class   => AuthorizationServerMiddlewareFactory::class,
            ResourceServerMiddleware::class        => ResourceServerMiddlewareFactory::class,

            /**
             * Services
             */
            AuthorizationServer::class             => AuthorizationServerFactory::class,
            ResourceServer::class                  => ResourceServerFactory::class,
            ClientService::class                   => ClientServiceFactory::class,
            ScopeService::class                    => ScopeServiceFactory::class,

            /**
             * Grant Services
             */
            ClientCredentialsGrant::class          => ClientCredentialsGrantFactory::class,
            PasswordGrant::class                   => PasswordGrantFactory::class,
            AuthorizationGrant::class                => AuthorizationGrantFactory::class,
            RefreshTokenGrant::class                 => RefreshTokenGrantFactory::class,

            /**
             * Utils
             */
            ServerOptions::class                     => ServerOptionsFactory::class,
            ManagerRegistry::class                   => My\ManagerRegistryFactory::class,

            /**
             * Factories that do not map to a class
             */
            TokenService::AUTHORIZATION_CODE_SERVICE => AuthorizationCodeServiceFactory::class,
            TokenService::ACCESS_TOKEN_SERVICE       => AccessTokenServiceFactory::class,
            TokenService::REFRESH_TOKEN_SERVICE      => RefreshTokenServiceFactory::class,
        ],
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
                    TokenOwnerInterface::class => My\Entity\User::class
                ],
            ],
        ],
        'driver'          => [
            'zfr_oauth2_driver' => [
                'class' => XmlDriver::class,
                'paths' => 'vendor/zfr/zfr-oauth2-server/config/doctrine',
            ],
            'orm_default'       => [
                'drivers' => [
                    'ZfrOAuth2\Server\Entity' => 'zfr_oauth2_driver',
                ],
            ],
        ],

        'configuration' => [
            'orm_default' => [
                'second_level_cache' => [
                    'enabled' => true,

                    'regions' => [
                        'oauth_token_region' => [
                            'lifetime' => 3600
                        ],

                        'oauth_scope_region' => [
                            'lifetime' => 300
                        ]
                    ],
                ],
            ],
        ],
    ],

    'zfr_oauth2_server' => [
        /**
         * Doctrine object manager key
         */
        // 'object_manager' => 'orm_default',

        /**
         * Various tokens TTL
         */
        // 'authorization_code_ttl' => 120,
        // 'access_token_ttl'       => 3600,
        // 'refresh_token_ttl'      => 86400,

        /**
         * Registered grants for this server
         */
        // 'grants'         => [],

        /**
         * A callable used to validate the username and password when using the
         * password grant
         */
        // 'owner_callable' => null,
    ],
];
