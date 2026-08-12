<?php

require(__DIR__ . "/../auth/session.php");

define("PWD_HASH", '$2a$08$Wx.0KRjfWhKxWhfhWx.0KO/kf0mdv9ELH7h2pYPwMlV3NoW9MmCUe');
define("VALID_PASSWD", "00000000");
define("INVALID_PASSWD", "xxxxxxxxx");
define("TOKEN_USER", "token/TokenRole/TokenDeviceId");
define("TOKEN_PASSWD", "01234567890123456789012345678901");
define("INVALID_TOKEN_USER", "token/TokenRole/InvalidDeviceId");
define("INVALID_TOKEN_PASSWD", "12345678901234567890123456789012");

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
		LockedOutInfo::unlinkFile("remoteconsole");

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

class TestBasicAuthWithToken extends Test
{
	public function run()
	{
		/* Remove all json files in /var/volatile/tokens */
		$files = glob("/var/volatile/tokens/*.json");
		if ($files !== false) {
			foreach ($files as $file) {
				@unlink($file);
			}
		}
		@unlink(TOKEN_FILE);
		LockedOutInfo::unlinkFile(TOKEN_USER);

		if (venus_authenticate_token(TOKEN_USER, TOKEN_PASSWD, $info) != VenusAuthStatus::InvalidUser)
			$this->assert("user should not be allowed to login when there is no token file");


		place_token_request(TOKEN_USER, TOKEN_PASSWD);
		/* Merge any token file in /var/volatile/tokens to TOKEN_FILE.
		 * 1. Create an empty array
		 * 2. For each json file in /var/volatile/tokens, decode it and add it to the array
		 * 3. Write the array to TOKEN_FILE
		 */
		$all_tokens = [];
		$files = glob("/var/volatile/tokens/*.json");
		if ($files !== false) {
			foreach ($files as $file) {
				$token = json_decode(file_get_contents($file), true);
				if ($token !== null) {
					$all_tokens[] = $token;
				}
			}
		}
		file_put_contents(TOKEN_FILE, json_encode($all_tokens, JSON_UNESCAPED_SLASHES));

		if (venus_authenticate_token(TOKEN_USER, TOKEN_PASSWD) != VenusAuthStatus::Allowed)
			$this->assert("invalid token user should not be allowed to login");

		if (venus_authenticate_token(null, TOKEN_PASSWD, $info) != VenusAuthStatus::InvalidUser)
			$this->assert("user should not be allowed to login when no username is given");

		if (venus_authenticate_token("", TOKEN_PASSWD, $info) != VenusAuthStatus::InvalidUser)
			$this->assert("user should not be allowed to login when no username is given");

		if (venus_authenticate_token(INVALID_TOKEN_USER, TOKEN_PASSWD, $info) != VenusAuthStatus::InvalidUser)
			$this->assert("invalid token user should not be allowed to login");

		if (venus_authenticate_token(TOKEN_USER, null, $info) != VenusAuthStatus::PasswordRequired)
			$this->assert("user should not be allowed to login when no password is given");

		for ($n = 0; $n < 10; $n++) {
			if (venus_authenticate_token(TOKEN_USER, INVALID_PASSWD, $info) != VenusAuthStatus::WrongPassword)
				$this->assert("10 attempts should be allowed before blocking");
		}

		if (venus_authenticate_token(TOKEN_USER, INVALID_PASSWD, $info) !== VenusAuthStatus::LockedOut)
			$this->assert("didn't get blocked after more then 10 attempts");

		$this->assertEqual($info->lockedout_till - $info->stamp, 120, "initial 2min lock out");

		if (venus_authenticate_token(TOKEN_USER, INVALID_PASSWD, $info) !== VenusAuthStatus::LockedOut)
			$this->assert("should still be locked out");
	}
}

class TestLockedOut extends Test
{
	public function run()
	{
		LockedOutInfo::unlinkFile("remoteconsole");
		LockedOutInfo::unlinkFile("not_remoteconsole");

		$info = LockedOutInfo::load("remoteconsole");

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

		$info2 = LockedOutInfo::load("not_remoteconsole");
		$this->assertEqual($info2->attempts_left, 10, "different user should have full attempts");
		$this->assertEqual($info2->lockedout_till, 0, "different user should not lock out");

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

		// initial attempt of different user name should not lock out
		for ($n = 10; --$n > 0; ) {
			$info2->loginAttempted(false);
			$this->assertEqual($info2->attempts_left, $n, "attempts should become less");
			$this->assertEqual($info2->lockedout_till, 0, "initial attempts should not lock out");
		}

		// the 10th of a different username will
		$info2->loginAttempted(false);
		$this->assertNotEqual($info2->lockedout_till, 0, "5: enough invalid attempts should lock out");
		$this->assertEqual($info2->lockedout_till - $info2->stamp, 120, "5: enough invalid attempts should lock out for 2 minutes");
		$this->assertEqual($info2->attempts_left, 1, "5: in locked state, there is only 1 attempt");

		$this->assertEqual($info->lockedout_till, 0, "5_1: a different user should not be locked out");
		$this->assertEqual($info->attempts_left, 10, "5_2: a different user should have full attempts");
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
	new TestLockedOut(),
	new TestVenusAuthenticate(),
	new TestBasicAuthWithToken()
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
