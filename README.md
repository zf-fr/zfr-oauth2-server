# ZfrOAuth2Server

[![Build Status](https://travis-ci.org/zf-fr/zfr-oauth2-server.png)](https://travis-ci.org/zf-fr/zfr-oauth2-server)
[![Latest Stable Version](https://poser.pugx.org/zfr/zfr-oauth2-server/v/stable.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)
[![Coverage Status](https://coveralls.io/repos/zf-fr/zfr-oauth2-server/badge.png)](https://coveralls.io/r/zf-fr/zfr-oauth2-server)
[![Scrutinizer Quality Score](https://scrutinizer-ci.com/g/zf-fr/zfr-oauth2-server/badges/quality-score.png?s=be36235c9898cfc55044f58d9bba789d2d4d102e)](https://scrutinizer-ci.com/g/zf-fr/zfr-oauth2-server/)
[![Total Downloads](https://poser.pugx.org/zfr/zfr-oauth2-server/downloads.png)](https://packagist.org/packages/zfr/zfr-oauth2-server)

ZfrOAuth2Server is a PHP library that aims to implement the OAuth 2 specification strictly. Contrary to other
libraries, it assumes you are using Doctrine, and provide various services based on Doctrine interfaces.

Currently, it's more of a proof of concept to implement a simpler and cleaner OAuth 2 server implementation. It
does not support yet the Implicit grant. If you want to help, please contribute!

If you need a full featured project, that was tested by thousands of people, I suggest you to have a look
at one of those two PHP libraries:

- [OAuth2 Server from PHP-League](https://github.com/php-loep/oauth2-server)
- [OAuth2 Server from Brent Shaffer](https://github.com/bshaffer/oauth2-server-php)

## Requirements

- PHP 5.4 or higher

## Versioning note

Please note that until I reach 1.0, I **WILL NOT** follow semantic version. This means that BC can occur between
0.1.x and 0.2.x releases. If you are using this in production, please set your dependency using 0.1.*, for instance.
