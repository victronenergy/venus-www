<?php

require("../auth/session.php");

define("PWD_HASH", '$2a$08$Wx.0KRjfWhKxWhfhWx.0KO/kf0mdv9ELH7h2pYPwMlV3NoW9MmCUe');
define("VALID_PASSWD", "00000000");
define("INVALID_PASSWD", "xxxxxxxxx");

class Test {
	public function assert($msg) {
		$name = get_class($this);
		throw new Exception("{$name} FAILED: $msg");
	}

	public function assertEqual($a, $b, $text) {
		if ($a != $b)
			$this->assert("$text assertEqual but  $a != $b");
	}

	public function assertNotEqual($a, $b, $text) {
		if ($a == $b)
			$this->assert("$text assertNotEqual, but $a == $b");
	}

	private string $name;
}

class TestVenusAuthenticate extends Test
{
	public function run()
	{
		@unlink(RATELIMIT_FILE);

		if (venus_authenticate(VALID_PASSWD, $info) != VenusAuthStatus::Allowed)
			$this->assert("valid password is not allowed to login");

		for ($n = 0; $n < 10; $n++) {
			if (venus_authenticate(INVALID_PASSWD, $info) != VenusAuthStatus::WrongPassword)
				$this->assert("10 attempts should be allowed before blocking");
		}

		if (venus_authenticate(INVALID_PASSWD, $info) !== VenusAuthStatus::LockedOut)
			$this->assert("didn't get blocked after more then 10 attempts");

		$this->assertEqual($info->lockedout_till - $info->stamp, 120, "initial 2min lock out");

		if (venus_authenticate(INVALID_PASSWD, $info) !== VenusAuthStatus::LockedOut)
			$this->assert("should still be locked out");
	}
}

class TestLockedOut extends Test
{
	public function run()
	{
		@unlink(RATELIMIT_FILE);

		$info = LockedOutInfo::load();

		// initial attempt should not lock out
		for ($n = 10; --$n > 0; ) {
			$info->loginAttempted(false);
			$this->assertEqual($info->attempts_left, $n, "attempts should become less");
			$this->assertEqual($info->lockedout_till, 0, "initial attempts should not lock out");
		}

		// the 10th will
		$info->loginAttempted(false);
		$this->assertNotEqual($info->lockedout_till, 0, "1: enough invalid attempts should lock out");
		$this->assertEqual($info->lockedout_till - $info->stamp, 120, "enough invalid attempts should lock out for 2 minutes");
		$this->assertEqual($info->attempts_left, 1, "1: in locked state, there is only 1 attempt");

		// lets fast forward time
		$info->stamp += 3 * 60;
		$info->loginAttempted(false);
		$this->assertNotEqual($info->lockedout_till, 0, "2: enough invalid attempts should lock out");
		$this->assertEqual($info->lockedout_till - $info->stamp, 240, "enough invalid attempts should lock out for 2 minutes");
		$this->assertEqual($info->attempts_left, 1, "2: in locked state, there is only 1 attempt");

		for ($n = 0; $n < 10; $n++) {
			$info->stamp += 2 * 60 * 60;
			$info->loginAttempted(false);
		}
		$this->assertNotEqual($info->lockedout_till, 0, "3: enough invalid attempts should lock out");
		$this->assertEqual($info->lockedout_till - $info->stamp, 64 * 60, "There is a maximum lockout time of 64 minutes");
		$this->assertEqual($info->attempts_left, 1, "in locked state, there is only 1 attempt");

		$info->loginAttempted(true);
		$this->assertEqual($info->lockedout_till, 0, "1: a valid login should reset the locked state");
		$this->assertEqual($info->attempts_left, 10, "2: a valid login should reset the locked state");

		for ($n = 10; --$n >= 0; )
			$info->loginAttempted(false);
		$this->assertNotEqual($info->lockedout_till, 0, "4: enough invalid attempts should lock out");

		$info->stamp += 25 * 60 * 60;
		$info->loginAttempted(true);
		$this->assertEqual($info->lockedout_till, 0, "1: if the device is no longer bombarded for quite some it should reset the locked state");
		$this->assertEqual($info->attempts_left, 10, "2: if the device is no longer bombarded for quite some it should reset the locked state");
	}
}

$fh = fopen(PWD_FILE, "w");
if ($fh === false) {
	print("can't open password file");
	exit(1);
}
if (!fwrite($fh, PWD_HASH)) {
	print("can't write password file");
	exit(1);
}
fclose($fh);

$tests = [
	new TestVenusAuthenticate(),
	new TestLockedOut()
];

$failed = 0;
foreach ($tests as $test) {
	try {
		$test->run();
		print(get_class($test) . " PASSED\n");
	} catch (Exception $e) {
		print($e->getMessage() . "\n");
		$failed++;
	}
}

if ($failed !== 0)
	exit(1)

?>
