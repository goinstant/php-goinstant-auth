<?php

require_once 'GoInstantAuth.php';

/**
 * Test constructor (which checks JWS parameters like keys).
 */
class ConstructorTest extends PHPUnit_Framework_TestCase {

  public function testNoKeySet() {
    $this->setExpectedException(
      'InvalidArgumentException', 'Secret Key must be a string'
    );
    new GoInstantAuth(NULL);
  }

  public function testNotBase64() {
    $this->setExpectedException(
      'InvalidArgumentException', 'Secret Key must be base64 or base64url'
    );
    new GoInstantAuth('$%^');
  }

  public function testNoBase64Padding() {
    // "GoInsta" -> "R29JbnN0YW=="
    $auth = new GoInstantAuth('R29JbnN0YW');
    $this->assertInstanceOf('GoInstantAuth', $auth);
  }
}

/**
 * Test token signature/creation.
 */
class SignTest extends PHPUnit_Framework_TestCase {

  private function validateJwt($jwt, $expectClaims, $expectSig='') {
    $parts = explode('.', $jwt);
    $this->assertCount(3, $parts);

    // validate header
    $this->assertRegExp('/^[a-z0-9_\-]+$/i', $parts[0]);
    $header = GoInstantAuth::compact_decode($parts[0]);
    $this->assertEquals(2, count($header));
    $this->assertEquals('JWT', $header['typ']);
    $this->assertEquals('HS256', $header['alg']);

    // validate payload (claims)
    $this->assertRegExp('/^[a-z0-9_\-]+$/i', $parts[1]);
    $claims = GoInstantAuth::compact_decode($parts[1]);
    $this->assertEquals($expectClaims, $claims);

    // since we currently only support HS256, the signature part is fixed-size:
    $this->assertRegExp('/^[a-z0-9_\-]{43}$/i', $parts[2]);
    $this->assertEquals($expectSig, $parts[2]);
  }

  protected function setUp() {
    $this->auth = new GoInstantAuth('HKYdFdnezle2yrI2_Ph3cHz144bISk-cvuAbeAAA999');
  }

  public function testNoClaims() {
    $this->setExpectedException(
      'InvalidArgumentException', 'userData must be an array'
    );

    $this->auth->sign(null);
  }

  public function testIdMissing() {
    $this->setExpectedException(
      'InvalidArgumentException', 'missing required key: id'
    );

    $this->auth->sign(array(
      'domain' => 'example.com',
      'displayName' => 'bob'
    ));
  }

  public function testDomainMissing() {
    $this->setExpectedException(
      'InvalidArgumentException', 'missing required key: domain'
    );

    $this->auth->sign(array(
      'id' => 'bar',
      'displayName' => 'bob'
    ));
  }

  public function testDisplayNameMissing() {
    $this->setExpectedException(
      'InvalidArgumentException', 'missing required key: displayName'
    );

    $this->auth->sign(array(
      'id' => 'bar',
      'domain' => 'example.com'
    ));
  }

  public function testGroupsNotArray() {
    $this->setExpectedException(
      'InvalidArgumentException', 'optional "groups" key must be an array'
    );

    $this->auth->sign(array(
      'id' => 'bar',
      'domain' => 'example.com',
      'displayName' => 'bob',
      'groups' => 'none'
    ));
  }

  public function testHappyNoGroups() {
    $jwt = $this->auth->sign(array(
      'id' => 'bar',
      'domain' => 'example.com',
      'displayName' => 'Bob',
      'groups' => array()
    ));

    $expectedSig = 'UOTAURbgnB9MtDRsHG3yK5-xwyvftnkPd1DCbVbwb3U';
    $this->validateJwt($jwt, array(
      'aud' => 'goinstant.net',
      'sub' => 'bar',
      'iss' => 'example.com',
      'dn' => 'Bob',
      'g' => array()
    ), $expectedSig);
  }

  public function testGroupMissingId() {
    $this->setExpectedException(
      'InvalidArgumentException', 'group 0 missing required key: id'
    );

    $this->auth->sign(array(
      'id' => 'bar',
      'domain' => 'example.com',
      'displayName' => 'Bob',
      'groups' => array(
        array('displayName' => 'MyGroup')
      )
    ));
  }

  public function testGroupMissingDisplayName() {
    $this->setExpectedException(
      'InvalidArgumentException', 'group 1 missing required key: displayName'
    );

    $this->auth->sign(array(
      'id' => 'bar',
      'domain' => 'example.com',
      'displayName' => 'Bob',
      'groups' => array(
        array('id' => 99, 'displayName' => 'Gretzky Lovers'),
        array('id' => 1234)
      )
    ));
  }

  public function testHappyGroups() {
    $jwt = $this->auth->sign(array(
      'id' => 'bar',
      'domain' => 'example.com',
      'displayName' => 'Bob',
      'groups' => array(
        array('id' => 1234, 'displayName' => 'Group 1234'),
        array('id' => 42, 'displayName' => 'Meaning Group')
      )
    ));

    $expectedSig = 'dudncYXmt1d1arfld8ayOX-2LrA6QKTmpCzs-FbXkAg';
    $this->validateJwt($jwt, array(
      'aud' => 'goinstant.net',
      'sub' => 'bar',
      'iss' => 'example.com',
      'dn' => 'Bob',
      'g' => array(
        array('id' => 1234, 'dn' => 'Group 1234'),
        array('id' => 42, 'dn' => 'Meaning Group')
      )
    ), $expectedSig);
  }
}

?>
