<?php
/**
 * GoInstantAuth is &copy; 2013 GoInstant Inc., a salesforce.com company.
 * All Rights Reserved.
 */

namespace GoInstant\Auth;

use \Exception;
use \InvalidArgumentException;

/**
 * GoInstant authentication utilities
 */
class Util {

  /**
   * Maps "user data" attributes to JWT claims.
   *
   * Modifies the <code>$claims</code> array in-place.
   *
   * @throws InvalidArgumentException
   * @return void
   */
  public static function mapRequiredClaims(&$claims, &$table, $msg='missing required key') {
    foreach ($table as $name => $jwtClaim) {
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
   * @return void
   */
  public static function mapOptionalClaims(&$claims, &$table) {
    foreach ($table as $name => $jwtClaim) {
      if (!isset($claims[$name])) {
        continue;
      }
      $tmp = $claims[$name];
      unset($claims[$name]);
      $claims[$jwtClaim] = $tmp;
    }
  }

  /**
   * Encodes a string as base64url.
   */
  public static function base64url_encode($str) {
    $str = base64_encode($str);
    if ($str === false) {
      throw new Exception('base64url encoding failed');
    }

    $str = str_replace('=','',$str);
    $str = str_replace('/','_',$str);
    $str = str_replace('+','-',$str);
    return $str;
  }

  /**
   * Decodes a base64url string.
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

    return Util::base64url_encode($json);
  }

  /**
   * Decodes Compact Serialization to produce an Array.
   *
   * @param string $str
   * @return array
   */
  public static function compact_decode($str) {
    $json = Util::base64url_decode($str);
    if ($json === false) {
      return false;
    }
    return json_decode($json, true);
  }

}
?>
