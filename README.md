# php-goinstant-auth

GoInstant Authentication for Your PHP Application.

[![Build Status](https://travis-ci.org/goinstant/php-goinstant-auth.png?branch=master)](https://travis-ci.org/goinstant/php-goinstant-auth)
[![Coverage Status](https://coveralls.io/repos/goinstant/php-goinstant-auth/badge.png)](https://coveralls.io/r/goinstant/php-goinstant-auth)

This is an implementation of JWT tokens consistent with what's specified in the
[GoInstant Users and Authentication
Guide](https://developers.goinstant.com/v1/security_and_auth/guides/users_and_authentication.html).

This library is not intended as a general-use JWT library; see JWT-php for
that. At the time of this writing, GoInstant supports the [JWT IETF draft
version 8](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08).

# Installation

## via Composer

Installing with [Composer](https://getcomposer.org) is easy:

```sh
  ./composer.phar require goinstant/goinstant-auth:dev-master
```

If not already done so by your framework, you can autoload composer modules
like so (assuming that this is in a file called `main.php` in your project
directory).

```php
  require_once 'vendor/autoload.php';
```

## via Zip-file

If you don't want to use Composer, we suggest that you download the [latest
release](https://github.com/goinstant/php-goinstant-auth/releases) zip-file off
of GitHub.  Extract the zip-file and you should get a `GoInstant` directory.
Copy this directory to your project library.

```sh
  cd ~/Downloads
  unzip php-goinstant-auth-*.zip

  cp -a php-goinstant-auth-*/GoInstant /path/to/your/project/GoInstant
```

Then, require the `Signer.php` file where you need to use it.  Note that you
may need to adjust the path based on the layout of your project.

```php
  require_once 'GoInstant/Auth/Signer.php';
```

# Usage

Creating a signer parses and stores your GoInstant application key.  The
application key should be in base64url or base64 string format. To get your
key, go to [your goinstant dashboard](https://goinstant.com/dashboard) and
click on your App.

**Remember, the Secret Key needs to be treated like a password!**
Never share it with your users!

```php
  use \GoInstant\Auth\Signer;
  $signer = new Signer($secretKey);
```

You can then use this `$signer` to create as many tokens as you want. You
should replace `example.com` with your website's domain. Groups are optional.

```php
  $token = $signer->sign(array(
    'domain' => 'example.com', // TODO: replace me
    'id' => $user->id,
    'displayName' => $user->fullName(),
    'groups' => array(
      array(
        'id' => 'room-'.$roomId,
        'displayName' => 'Room '.$roomId
      )
    )
  ));
```

You can then inline this into your goinstant connection JavaScript.  The JWT
format is safe to inline in both URL and HTML contexts since it only contains
characters matched by `/^[a-zA-Z0-9_\-.]+$/`

```php
<script type="text/javascript">
  (function() {
    // using a var like this prevents other javascript on the page from
    // easily accessing or stealing the token:
    var opts = {
      user: "<?php echo $token ?>",
      rooms: [ ... ]
    };
    var url = 'https://goinstant.net/YOURACCOUNT/YOURAPP'

    goinstant.connect(url, opts, function(err, connection) {
      if (err) {
        throw err;
      }
      runYourApp(connection);
    });
  }());
</script>
```

# Methods

### `__constructor($secretKey)`

Constructs a `GoInstantAuth` "signer" instance from a secret key.

### `sign($userData, $extraHeaders=array())`

Creates a JWT as a JWS in Compact Serialization format.  Can be called multiple
times on the same object, saving you from having to load your secret GoInstant
application key every time.

`$userData` is an Array with the following required fields, plus any other
custom ones you want to include in the JWT.

- `domain` - the domain of your website
- `id` - the unique, permanent identity of this user on your website
- `displayName` - the name to initially display for this user
- `groups` - an array of groups, each group requiring:
  - `id` - the unique ID of this group, which is handy for defining [GoInstant ACLs](https://developers.goinstant.com/v1/security_and_auth/guides/creating_and_managing_acl.html)
  - `displayName` - the name to display for this group

`$extraHeaders` is completely optional.  It's used to define any additional
[JWS header fields](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-11#section-4.1)
that you want to include.

# Technicals

The `sign()` method `$userData` maps to the following JWT claims.
The authoritative list of claims used in GoInstant can be found in the
[Users and Authentication Guide](https://developers.goinstant.com/v1/security_and_auth/guides/users_and_authentication.html#which-reserved-claims-are-required).

- `domain` -> `iss` (standard claim)
- `id` -> `sub` (standard claim)
- `displayName` -> `dn` (GoInstant private claim)
- `groups` -> `g` (GoInstant private claim)
  - `id` -> `id` (GoInstant private claim)
  - `displayName` -> `dn` (GoInstant private claim)
- `'goinstant.net'` -> `aud` (standard claim) _automatically added_

For the `$extraHeaders` parameter in `sign()`, the `alg` and `typ` headers will
be overridden by this library.

# Contributing

If you'd like to contribute to or modify php-goinstant-auth, here's a quick
guide to get you started.

## Development Dependencies

- [PHP](http://www.php.net/downloads.php) >= 5.3 (5.5 recommended)
- [Composer](https://getcomposer.org/download/) >= 1.0.0-alpha7

## Set-Up

Download via GitHub and install composer dependencies:

```sh
git clone git@github.com:goinstant/php-goinstant-auth.git
cd php-goinstant-auth
```

If you're developing on a Mac, you may wish to install php and composer through
Mac Homebrew via the `brew install` command.  Otherwise, follow the
instructions on [the Composer download page](https://getcomposer.org/download/).

```sh
composer install || ./composer.phar install
```

## Testing

Tests are written in PHPUnit. The test files themselves are located in the
`Tests/` directory.

To run the tests:

```sh
vendor/bin/phpunit
```

This may fail on the Coverage step if your PHP doesn't have the XDebug
extension loaded.  Either remove the coverage step from `phpunit.xml` or
edit your `php.ini` to include the XDebug extension. XDebug can be
installed via PEAR or through Mac Homebrew.

## Publishing

When publishing master to a new `$VERSION` (a semver)

1. edit composer.json to bump the version number
2. `git add -u && git commit -m "$VERSION"`
3. `git tag $VERSION`
4. `git push origin master`
5. `git push --tags`

Go to https://packagist.org/packages/goinstant/goinstant-auth and confirm it published.

# Support

Email [GoInstant Support](mailto:support@goinstant.com) or stop by [#goinstant on freenode](irc://irc.freenode.net/#goinstant).

For responsible disclosures, email [GoInstant Security](mailto:security@goinstant.com).

To [file a bug](https://github.com/goinstant/php-goinstant-auth/issues) or
[propose a patch](https://github.com/goinstant/php-goinstant-auth/pulls),
please use github directly.

# Legal

&copy; 2013 GoInstant Inc., a salesforce.com company.  All Rights Reserved.

Licensed under the 3-clause BSD license
