<?php

/**
 * GoInstantAuth - GoInstant Authentication for Your PHP Application
 *
 * This is an implementation of JWT tokens consistent with what's specified at
 * https://developers.goinstant.com/v1/guides/users_and_authentication.html
 *
 * This library is not intended as a general-use JWT library; see JWT-php for
 * that. At the time of this writing, GoInstant supports the JWT IETF draft
 * version 8
 * https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08
 *
 * Usage:
 *
 * <pre>
 *   $auth = new GoInstantAuth($myBase64AppKey);
 *   // ...
 *   $token = $auth->sign(array(
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
class GoInstantAuth {

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

    $this->_binaryKey = GoInstantAuth::base64url_decode($secretKey);
    $secretKey = trim($secretKey);

    // convert from base64url
    $secretKey = str_replace('_','/',$secretKey);
    $secretKey = str_replace('-','+',$secretKey);

    $this->_binaryKey = base64_decode($secretKey, true);
    if ($this->_binaryKey === false) {
      throw new InvalidArgumentException('Secret Key must be base64 or base64url');
    }
  }

  /**
   * Converts "userData" (i.e. options) to a JWT claims array.
   *
   * @ignore
   * @param array $userData associative-array of user properties
   * @return array converted claims
   */
  function userDataToClaims($userData) {
    if (is_null($userData) || !is_array($userData)) {
      throw new InvalidArgumentException('userData must be an array');
    }

    $claims = $userData; // copy

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

    GoInstantAuth::mapRequiredClaims($claims, $REQUIRED);
    GoInstantAuth::mapOptionalClaims($claims, $OPTIONAL);

    // clean up groups sub-structure

    if (isset($claims['g'])) {
      if (!is_array($claims['g'])) {
        throw new InvalidArgumentException(
          'optional "groups" key must be an array'
        );
      }

      foreach ($claims['g'] as $i => $group) {
        $group = $group; // clone
        GoInstantAuth::mapRequiredClaims(
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
   * Creates a JWT based on the supplied user data.
   *
   * The following properties are required:
   * <ul>
   *   <li><b>domain</b> The top-level domain of your system</li>
   *   <li><b>id</b> The identity of this user on your system</li>
   *   <li><b>displayName</b> The name you want to display initially for this user</li>
   * </ul>
   *
   * Optionally, a <b>groups</b> array can be passed in.  Each group is required to have:
   * <ul>
   *   <li><b>id</b> The identity of this group</li>
   *   <li><b>displayName</b> The name you want to display for this group</li>
   * </ul>
   *
   * @param array $userData associative-array of user properties
   * @return string a JWT in JWS format for use with GoInstant
   */
  public function sign($userData, $extraHeader=array()) {
    $claims = $this->userDataToClaims($userData);

    $header = $extraHeader; // copy
    // overwrite:
    $header['typ'] = 'JWT';
    $header['alg'] = 'HS256';

    $jwsProtectedHeader = GoInstantAuth::compact_encode($header);
    $jwsPayload = GoInstantAuth::compact_encode($claims);
    $jwsSigningInput = $jwsProtectedHeader . '.' . $jwsPayload;

    $sig = GoInstantAuth::base64url_encode(hash_hmac(
      'sha256',
      $jwsSigningInput,
      $this->_binaryKey,
      true
    ));

    return $jwsSigningInput . '.' . $sig;
  }

  /// Class Members ///

  /**
   * Encodes a string as base64url.
   * @ignore
   */
  public static function base64url_encode($str) {
    $str = base64_encode($str);
    if ($str === false) {
      throw new Exception('GoInstantAuth: base64url encoding failed');
    }

    $str = str_replace('=','',$str);
    $str = str_replace('/','_',$str);
    $str = str_replace('+','-',$str);
    return $str;
  }

  /**
   * Decodes a base64url string.
   * @ignore
   */
  public static function base64url_decode($str) {
    $str = trim($str);
    $str = str_replace('_','/',$str);
    $str = str_replace('-','+',$str);
    return base64_decode($str, true);
  }

  /**
   * Encodes an Array ("Object") in Compact Serialization form.
   *
   * Compact Serialization is defined in the JWT/JOSE specs as
   * base64url-encoded JSON, with '.' delimiters.
   * @ignore
   * @param array $o associative-array to encode
   * @return string
   */
  public static function compact_encode($o) {
    if (defined('JSON_UNESCAPED_SLASHES')) {
      $json = json_encode($o, JSON_UNESCAPED_SLASHES);
    } else {
      $json = json_encode($o);
      if ($json !== false) {
        $json = str_replace('\\/','/', $json);
      }
    }

    if ($json === false) {
      throw new Exception('JSON encoding failed: '.json_last_error_msg());
    }

    return GoInstantAuth::base64url_encode($json);
  }

  /**
   * Decodes Compact Serialization to produce an Array.
   *
   * @ignore
   * @param string $str
   * @return array
   */
  public static function compact_decode($str) {
    $json = GoInstantAuth::base64url_decode($str);
    if ($json === false) {
      return false;
    }
    return json_decode($json, true);
  }

  /**
   * Maps "user data" attributes to JWT claims.
   *
   * Modifies the <code>$claims</code> array in-place.
   *
   * @ignore
   * @throws InvalidArgumentException
   * @return void
   */
  static function mapRequiredClaims(&$claims, &$table, $msg='missing required key') {
    foreach($table as $name => $jwtClaim) {
      if (!isset($claims[$name])) {
        throw new InvalidArgumentException($msg.': '.$name);
      }
      $tmp = $claims[$name];
      unset($claims[$name]);
      $claims[$jwtClaim] = $tmp;
    }
  }

  /**
   * Maps optional "user data" attributes to JWT claims.
   *
   * Modifies the <code>$claims</code> array in-place.
   *
   * @ignore
   * @return void
   */
  static function mapOptionalClaims(&$claims, &$table) {
    foreach($table as $name => $jwtClaim) {
      if (!isset($claims[$name])) {
        continue;
      }
      $tmp = $claims[$name];
      unset($claims[$name]);
      $claims[$jwtClaim] = $tmp;
    }
  }
}
?>
