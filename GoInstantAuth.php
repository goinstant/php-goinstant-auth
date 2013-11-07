<?php
class GoInstantAuth {

  /// Class Members ///

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

  public static function base64url_decode($str) {
    $str = trim($str);
    $str = str_replace('_','/',$str);
    $str = str_replace('-','+',$str);
    return base64_decode($str, true);
  }

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

  public static function compact_decode($str) {
    $json = GoInstantAuth::base64url_decode($str);
    if ($json === false) {
      return false;
    }
    return json_decode($json, true);
  }

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

  /// Instance Members ///

  private $_binaryKey = null;

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
}
?>
