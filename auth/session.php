<?php

/*
 * To avoid errors from breaking http_response_code(). This makes development harder, but there
 * is no good way around this.
 */
error_reporting(0);

define("PWD_FILE", "/data/conf/vncpassword.txt");
define("MAX_LOGIN_ATTEMPTS", 10);
define("MAX_LOCK_LEVEL", 6);
define("LOCKOUT_TIME", (2 * 60));
define("LOCKOUT_IDLE_RESET", (24 * 60 * 60));
define("SESSION_ID", "VENUS_SESSION_ID");

enum VenusAuthStatus: string {
	case Allowed = "Allowed";
	case AllowedUnsecured = "AllowedUnsecured";
	case NotConfigured = "NotConfigured";
	case WrongPassword = "WrongPassword";
	case PasswordRequired = "PasswordRequired";
	case InvalidUser = "InvalidUser";
	case LockedOut = "LockedOut";

	public function toString(): string {
		return $this->value;
	}
}

function venus_session_start(bool $readonly = false)
{
	if (session_start([
		'cookie_lifetime' => 365 * 24 * 60 * 60,
		'gc_maxlifetime' => 365 * 24 * 60 * 60,
		'read_and_close'  => $readonly,
		'name' => SESSION_ID,
		'save_path' => '/data/var/lib/venus-www-sessions'
	]) === false) {
			http_response_code(500); // Internal Server Error
			exit();
	}
}

class LockedOutInfo implements JsonSerializable {
	public $last_attempt_at;
	public $attempts_left;
	public $lockedout_level;
	public $lockedout_till;
	public $stamp;

	// note: use load instead, a flock will be held till close is called or
	// the object is destructed.
	private function __construct($fh, mixed $data = [])
	{
		$this->last_attempt_at = $data->last_attempt_at ?? 0;
		$this->attempts_left = $data->attempts_left ?? MAX_LOGIN_ATTEMPTS;
		$this->lockedout_level = $data->lockedout_level ?? 0;
		$this->lockedout_till = $data->lockedout_till ?? 0;

		$this->fh = $fh;
		$this->stamp = hrtime()[0];
	}

	public function __destruct()
	{
		$this->close();
	}

	public function jsonSerialize(): mixed
	{
		return [
			'last_attempt_at' => $this->last_attempt_at,
			'attempts_left' => $this->attempts_left,
			'lockedout_level' => $this->lockedout_level,
			'lockedout_till' => $this->lockedout_till
		];
	}

	public function lockedOutDuration(): int
	{
		if ($this->lockedout_till === 0)
			return 0;

		if ($this->stamp > $this->lockedout_till)
			return 0;

		return $this->lockedout_till - $this->stamp;
	}

	private static function getFilename(string $username = "remoteconsole"): string
	{
		// Encode username to URL-safe base64 for the filename
		$encoded_username = rtrim(strtr(base64_encode($username), '+/', '-_'), '=');
		return "/tmp/nginx-auth-ratelimit-" . $encoded_username . ".json";
	}

	public static function load(string $username): LockedOutInfo
	{
		$fh = fopen(self::getFilename($username), "c+");

		if ($fh  === false) {
			http_response_code(500); // Internal Server Error
			exit(1);
		}

		flock($fh, LOCK_EX);

		$json = fgets($fh);
		$info = json_decode($json);
		$ret = new LockedOutInfo($fh, $info);

		return $ret;
	}

	public function save()
	{
		ftruncate($this->fh, 0);
		fseek($this->fh, 0);
		$json = json_encode($this);
		fwrite($this->fh, $json);
		fflush($this->fh);
	}

	// note: close also unlocks the file
	public function close()
	{
		if ($this->fh === false)
			return;

		fclose($this->fh);
		$this->fh = false;
	}

	private function reset()
	{
		$this->attempts_left = MAX_LOGIN_ATTEMPTS;
		$this->lockedout_level = 0;
		$this->lockedout_till = 0;
	}

	public function loginAttempted(bool $correct)
	{
		if ($correct) {
			$this->reset();
		} else {
			// When left alone for a long time, reset the lock level.
			if ($this->last_attempt_at !== 0 && $this->last_attempt_at < $this->stamp &&
					($this->stamp - $this->last_attempt_at) > LOCKOUT_IDLE_RESET)
				$this->reset();

			if ($this->attempts_left)
				$this->attempts_left--;

			if ($this->attempts_left === 0) {
				if ($this->lockedout_level < MAX_LOCK_LEVEL)
					$this->lockedout_level++;

				$this->attempts_left = 1;
				$duration = pow(2, $this->lockedout_level - 1) * LOCKOUT_TIME;
				$this->lockedout_till = $this->stamp + $duration;
			}
		}

		$this->last_attempt_at = $this->stamp;
		$this->save();
	}

	private $fh;
};

// only check if a password is valid
// Note: the optional info can be used to report the current lock status.
// It is closed though, so it cannot be modified.
function venus_authenticate(?string $password, &$info = null): VenusAuthStatus
{
	$configured = file_exists(PWD_FILE);
	if (!$configured)
		return VenusAuthStatus::NotConfigured;

	$hash = @file_get_contents(PWD_FILE);
	if ($hash === false) {
		http_response_code(500); // Internal Server Error
		exit();
	}

	$hash = trim($hash);
	if ($hash === "")
		return VenusAuthStatus::AllowedUnsecured;

	if (is_null($password))
		return VenusAuthStatus::PasswordRequired;

	$info = LockedOutInfo::load("remoteconsole");

	$lockout_duration = $info->lockedOutDuration();
	if ($lockout_duration > 0) {
		$info->close();
		return VenusAuthStatus::LockedOut;
	}

	$correct = password_verify($password, $hash);
	$info->loginAttempted($correct);
	$info->close();

	return ($correct === true ? VenusAuthStatus::Allowed : VenusAuthStatus::WrongPassword);
}

// like above, only succeeds if the basic password matches
function venus_authenticate_basic_auth(&$info = null): VenusAuthStatus
{
	if ($_SERVER['PHP_AUTH_USER'] !== "remoteconsole")
		return VenusAuthStatus::InvalidUser;

	return venus_authenticate($_SERVER['PHP_AUTH_PW'] ?? null, $info);
}

/*
 * Check if the password is valid or if this is an already logged in user
 * For a valid login it will start a session, if not the session will be
 * destroyed, to prevent having a lot of invalid session files.
 * Passing no password or null is fine, the function only checks if there
 * is a valid sessions in that case.
 */
function venus_authenticate_session(?string $password = null, &$info = null): VenusAuthStatus
{
	$status = venus_authenticate($password, $info);

	// note: don't start a session in this case, since requests without proper cookie
	// support will cause lots of session files.
	if ($status === VenusAuthStatus::AllowedUnsecured)
		return $status;

	if ($status === VenusAuthStatus::Allowed) {
		venus_session_start();
		$_SESSION["remoteconsole-authenticated"] = true;
		return $status;
	}

	if (!isset($_COOKIE[SESSION_ID]))
		return $status;

	venus_session_start();

	if (!empty($_SESSION["remoteconsole-authenticated"]))
		return VenusAuthStatus::Allowed;

	return $status;
}
