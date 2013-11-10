# php-goinstant-auth

GoInstant Authentication for Your PHP Application

This is an implementation of JWT tokens consistent with what's specified in the
[GoInstant Users and Authentication
Guide](https://developers.goinstant.com/v1/guides/users_and_authentication.html).

This library is not intended as a general-use JWT library; see JWT-php for
that. At the time of this writing, GoInstant supports the [JWT IETF draft
version 8](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08).


# Usage

Creating a signer parses and stores your GoInstant application key.  The
application key should be in base64url or base64 string format.

:warning: **Remember, the Secret Key needs to be treated like a password!**
Never share it with your users!

```php
  $signer = new GoInstantAuth($yourGoInstantAppKey);
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

You can then inline this into your goinstant connection JavaScript.  The JWT format is safe to inline in both URL and HTML contexts since it only contains characters matched by `/^[a-zA-Z0-9_\-.]+$/`

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

Creates a JWT as a JWS in Compact Serialization format.  Can be called multiple times on the same object, saving you from having to load your secret GoInstant application key every time.

`$userData` is an Array with the following required fields, plus any other
custom ones you want to include in the JWT.
- `domain` - the domain of your website
- `id` - the unique, permanent identity of this user on your website
- `displayName` - the name to initially display for this user
- `groups` - an array of groups, each group requiring:
  - `id` - the unique ID of this group, which is handy for defining [GoInstant ACLs](https://developers.goinstant.com/v1/guides/creating_and_managing_acl.html)
  - `displayName` - the name to display for this group

`$extraHeaders` is completely optional.  It's used to define any additional
[JWS header fields](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-11#section-4.1)
that you want to include.

# Technicals

The `sign()` method `$userData` maps to the following JWT claims:
- `domain` -> `iss` (standard claim)
- `id` -> `sub` (standard claim)
- `displayName` -> `dn` (GoInstant private claim)
- `groups` -> `g` (GoInstant private claim)
  - `id` -> `id` (GoInstant private claim)
  - `displayName` -> `dn` (GoInstant private claim)
- `'goinstant.net'` -> `aud` (standard claim) _automatically added_

For the `$extraHeaders` parameter in `sign()`, the `alg` and `typ` headers will
be overridden by this library.

# Legal

&copy; 2013 GoInstant Inc., a salesforce.com company.  All Rights Reserved.

Licensed under the 3-clause BSD license
