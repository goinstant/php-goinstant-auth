<?php
/**
 * GoInstantAuth is &copy; 2013 GoInstant Inc., a salesforce.com company.
 * All Rights Reserved.
 */

namespace GoInstant\Auth;

require_once 'Util.php';

use \InvalidArgumentException;
use \GoInstant\Auth\Util;


/**
 * Converts "userData" (i.e. options) to a JWT claims array.
 *
 * @param array $userData associative-array of user properties
 * @return array converted claims
 */
function userDataToClaims($userData) {
  if (is_null($userData) || !is_array($userData)) {
    throw new InvalidArgumentException('userData must be an array');
  }

  $claims = $userData; // copy
  $claims['aud'] = 'goinstant.net';

  // required claims
  $REQUIRED = array(
    'id' => 'sub',
    'domain' => 'iss',
    'displayName' => 'dn'
  );
  $OPTIONAL = array(
    'groups' => 'g'
  );

  $GROUP_REQUIRED = array(
    'id' => 'id',
    'displayName' => 'dn'
  );

  Util::mapRequiredClaims($claims, $REQUIRED);
  Util::mapOptionalClaims($claims, $OPTIONAL);

  // clean up groups sub-structure

  if (isset($claims['g'])) {
    if (!is_array($claims['g'])) {
      throw new InvalidArgumentException(
        'optional "groups" key must be an array'
      );
    }

    foreach ($claims['g'] as $i => $group) {
      $group = $group; // clone
      Util::mapRequiredClaims(
        $group,
        $GROUP_REQUIRED,
        "group $i missing required key"
      );
      $claims['g'][$i] = $group;
    }
  }

  return $claims;
}

/**
 * Auth - GoInstant token factory for your PHP application
 *
 * This is an implementation of JWT tokens consistent with what's specified in
 * the <a href="https://developers.goinstant.com/v1/guides/users_and_authentication.html">GoInstant Users and Authentication Guide</a>.
 *
 * This library is not intended as a general-use JWT library; see JWT-php for
 * that. At the time of this writing, GoInstant supports the
 * <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08">JWT IETF draft version 8</a>
 *
 * Usage:
 *
 * <pre>
 *   use \GoInstant\Auth\Signer;
 *   $signer = new Signer($myBase64AppKey);
 *   // ...
 *   $token = $signer->sign(array(
 *     'domain' => 'mydomain.com',
 *     'id' => $user->id,
 *     'displayName' => $user->fullName(),
 *     'groups' => array(
 *       array(
 *         'id' => 'room-'.$roomId,
 *         'displayName' => 'Room '.$roomId
 *       )
 *     )
 *   ));
 * </pre>
 */
class Signer {

  /// Instance Members ///

  /**
   * The decoded GoInstant app key (i.e. binary string)
   * @ignore
   */
  private $_binaryKey = null;

  /**
   * Initializes this factory with a given GoInstant app key.
   *
   * @param string $secretKey base64 or base64url GoInstant app key
   */
  public function __construct($secretKey) {
    if (is_null($secretKey) || !is_string($secretKey)) {
      throw new InvalidArgumentException('Secret Key must be a string');
    }

    $this->_binaryKey = Util::base64url_decode($secretKey);
    if ($this->_binaryKey === false) {
      throw new InvalidArgumentException('Secret Key must be base64 or base64url');
    }
  }

  /**
   * Creates a JWT based on the supplied user data.
   *
   * The following properties are required:
   * <ul>
   *   <li><b>domain</b> The top-level domain of your system</li>
   *   <li><b>id</b> The identity of this user on your system</li>
   *   <li><b>displayName</b> The name you want to display initially for this
   *   user</li>
   * </ul>
   *
   * Optionally, a <b>groups</b> array can be passed in.  Each group is
   * required to have:
   * <ul>
   *   <li><b>id</b> The identity of this group</li>
   *   <li><b>displayName</b> The name you want to display for this group</li>
   * </ul>
   *
   * @param array $userData associative-array of user properties
   * @param array $extraHeader optional claims for the JWT header.  See the
   * JWT/JWS spec for valid items.
   * @return string a JWT in Compact JWS format for use with GoInstant
   */
  public function sign($userData, $extraHeader=array()) {
    $claims = userDataToClaims($userData);

    $header = $extraHeader; // copy
    // overwrite:
    $header['typ'] = 'JWT';
    $header['alg'] = 'HS256';

    $jwsProtectedHeader = Util::compact_encode($header);
    $jwsPayload = Util::compact_encode($claims);
    $jwsSigningInput = $jwsProtectedHeader . '.' . $jwsPayload;

    $sig = Util::base64url_encode(hash_hmac(
      'sha256',
      $jwsSigningInput,
      $this->_binaryKey,
      true
    ));

    return $jwsSigningInput . '.' . $sig;
  }
}
?>
