<?php

require_once './GoInstantAuth.php';

class UnitTest extends PHPUnit_Framework_TestCase {

  public function testCreate() {
    $auth = new GoInstantAuth();
    $token = $auth->sign(array());
  }
}

?>
