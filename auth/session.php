<?php

define("PWD_FILE", "/data/conf/vncpassword.txt");

enum VenusAuthStatus: string {
	case Allowed = "Allowed";
	case NotConfigured = "NotConfigured";
	case WrongPassword = "WrongPassword";
	case PasswordRequired = "PasswordRequired";
	case InvalidUser = "InvalidUser";

	public function toString(): string {
		return $this->value;
	}
}

function venus_session_start(bool $readonly = false)
{
	session_start([
		'cookie_lifetime' => 365 * 24 * 60 * 60,
		'read_and_close'  => $readonly,
		'name' => 'VENUS_SESSION_ID',
		'save_path' => '/data/var/lib/venus-www-sessions'
	]);
}

// only check if a password is valid
function venus_authenticate(string $password): VenusAuthStatus
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
	if ($hash == "")
		return VenusAuthStatus::Allowed;

	if (password_verify($password, $hash))
		return VenusAuthStatus::Allowed;

	return VenusAuthStatus::WrongPassword;
}

// like above, only succeeds if the basic password matches
function venus_authenticate_basic_auth(): VenusAuthStatus
{
	if ($_SERVER['PHP_AUTH_USER'] !== "remoteconsole")
		return VenusAuthStatus::InvalidUser;

	if (!isset($_SERVER['PHP_AUTH_PW']))
		return VenusAuthStatus::PasswordRequired;

	return venus_authenticate($_SERVER['PHP_AUTH_PW']);
}

/*
 * Check if the password is valid or if this is an already logged in user
 * For a valid login it will start a session, if not the session will be
 * destroyed, to prevent having a lot of invalid session files.
 * Passing no password or null is fine, the function only checks if there
 * is a valid sessions in that case.
 */
function venus_authenticate_session(?string $password = null): VenusAuthStatus
{
	venus_session_start();

	if (!is_null($password)) {
		$status = venus_authenticate($password);
		if ($status === VenusAuthStatus::Allowed)
			$_SESSION["remoteconsole-authenticated"] = true;
		else
			session_destroy();

		return $status;
	}

	if (!empty($_SESSION["remoteconsole-authenticated"]))
		return VenusAuthStatus::Allowed;

	session_destroy();
	return VenusAuthStatus::PasswordRequired;
}
?>