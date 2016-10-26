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

use ZfrOAuth2\Server\AuthorizationServerInterface;
use ZfrOAuth2\Server\Container\AccessTokenServiceFactory;
use ZfrOAuth2\Server\Container\AuthorizationCodeServiceFactory;
use ZfrOAuth2\Server\Container\AuthorizationGrantFactory;
use ZfrOAuth2\Server\Container\AuthorizationRequestMiddlewareFactory;
use ZfrOAuth2\Server\Container\AuthorizationServerFactory;
use ZfrOAuth2\Server\Container\ClientCredentialsGrantFactory;
use ZfrOAuth2\Server\Container\ClientServiceFactory;
use ZfrOAuth2\Server\Container\PasswordGrantFactory;
use ZfrOAuth2\Server\Container\RefreshTokenGrantFactory;
use ZfrOAuth2\Server\Container\RefreshTokenServiceFactory;
use ZfrOAuth2\Server\Container\ResourceServerFactory;
use ZfrOAuth2\Server\Container\ResourceServerMiddlewareFactory;
use ZfrOAuth2\Server\Container\RevocationRequestMiddlewareFactory;
use ZfrOAuth2\Server\Container\ScopeServiceFactory;
use ZfrOAuth2\Server\Container\ServerOptionsFactory;
use ZfrOAuth2\Server\Container\TokenRequestMiddlewareFactory;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Middleware\AuthorizationRequestMiddleware;
use ZfrOAuth2\Server\Middleware\ResourceServerMiddleware;
use ZfrOAuth2\Server\Middleware\RevocationRequestMiddleware;
use ZfrOAuth2\Server\Middleware\TokenRequestMiddleware;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\ResourceServerInterface;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\RefreshTokenService;
use ZfrOAuth2\Server\Service\ScopeService;

return [
    'dependencies' => [
        'factories' => [
            /**
             * Middleware
             */
            AuthorizationRequestMiddleware::class => AuthorizationRequestMiddlewareFactory::class,
            RevocationRequestMiddleware::class    => RevocationRequestMiddlewareFactory::class,
            TokenRequestMiddleware::class         => TokenRequestMiddlewareFactory::class,
            ResourceServerMiddleware::class       => ResourceServerMiddlewareFactory::class,

            /**
             * Services
             */
            AuthorizationServerInterface::class   => AuthorizationServerFactory::class,
            ResourceServerInterface::class        => ResourceServerFactory::class,
            ClientService::class                  => ClientServiceFactory::class,
            ScopeService::class                   => ScopeServiceFactory::class,
            AuthorizationCodeService::class       => AuthorizationCodeServiceFactory::class,
            AccessTokenService::class             => AccessTokenServiceFactory::class,
            RefreshTokenService::class            => RefreshTokenServiceFactory::class,

            /**
             * Grant Services
             */
            ClientCredentialsGrant::class         => ClientCredentialsGrantFactory::class,
            PasswordGrant::class                  => PasswordGrantFactory::class,
            AuthorizationGrant::class             => AuthorizationGrantFactory::class,
            RefreshTokenGrant::class              => RefreshTokenGrantFactory::class,

            /**
             * Utils
             */
            ServerOptions::class                  => ServerOptionsFactory::class,
        ],
    ],
];
