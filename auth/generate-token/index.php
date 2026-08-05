<?php

/*
 * Allow to add a token by an authenticated user, for testing:
 * curl -k -v --user "remoteconsole:00000000" -d "role=test&device_id=test" https://xxx.xxx.xxx.xxx/auth/generate-token/
 */

require('../session.php');

function generate_random_string(int $length = 32): string
{
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$charactersLength = strlen($characters);
	$randomString = '';
	for ($i = 0; $i < $length; $i++)
		$randomString .= $characters[random_int(0, $charactersLength - 1)];

	return $randomString;
}

function get_system_uptime_in_seconds(): int
{
	$uptimeFile = '/proc/uptime';

	if (!is_readable($uptimeFile))
		return -1;

	$content = file_get_contents($uptimeFile);

	if ($content === false)
		return -1;

	$parts = explode(' ', $content);
	return intval($parts[0]);
}

/*
 * Places a json file with the token to be added to the token database.
 * Venus Platform will look at the watched dir and actually add them.
 */
function place_token_request(string $token_name, string $password): void
{
	// note: this should be on the same parition as /tmp
	static $watched_dir = "/var/volatile/tokens";

	if (!is_dir($watched_dir))
		throw new Exception("Directory $watched_dir is not there.");

	if (!is_writable($watched_dir))
		throw new Exception("Directory $watched_dir is not writable.");

	$tmp_path = tempnam("/tmp", "tmp_new_token_");
	if ($tmp_path === false)
		throw new Exception("Can't create temp file for token generation");

	$user_data = [
		'token_name' => $token_name,
		'password_hash' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 4])
	];
	$new_json_text = json_encode($user_data, JSON_UNESCAPED_SLASHES);

	$tmp_file_handle = fopen($tmp_path, "w");

	if ($tmp_file_handle === false)
		throw new Exception("Can't open file for writing");

	$write_result = fwrite($tmp_file_handle, $new_json_text);
	fsync($tmp_file_handle);
	fclose($tmp_file_handle);

	if ($write_result === false) {
		unlink($tmp_path);
		throw new Exception("Failed to write new tokens file");
	}

	// Save the file uniquely per token_name, if multiple simultaneous request are
	// made the last one will win. base64 encode it, so .. and / etc cannot be used
	// to write to a different directory.
	$new_token_file_path = $watched_dir . "/" . base64_encode($token_name) . ".json";
	if (rename($tmp_path, $new_token_file_path) === false) {
		unlink($tmp_path);
		throw new Exception("Renaming to final file failed");
	}
}

function get_query_argument(string $arg_name): ?string
{
	$val = $_POST[$arg_name] ?? null;

	if (empty($val)) {
		http_response_code(400);
		print("POST argument $arg_name is required\n");
		exit();
	}

	if (preg_match("/^\w+$/", $val) !== 1) {
		http_response_code(400);
		print("$arg_name can only contain alpha-numerics.\n");
		exit();
	}

	return $val;
}

// Venus Platform sets the pairing mode.
function in_pairing_mode() : bool
{
	static $signal_file = "/var/volatile/tokens/pairing.json";

	if (!file_exists($signal_file))
		return false;

	$bytes = file_get_contents($signal_file);

	if ($bytes === false)
		return false;

	$data = json_decode($bytes);

	if ($data === false)
		return false;

	if (!property_exists($data, 'expires_at'))
		return false;

	$current_uptime = get_system_uptime_in_seconds();

	if ($current_uptime < 0)
		return false;

	$expires_at = intval($data->expires_at);
	return $expires_at > $current_uptime;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	http_response_code(400);
	print("Method must be POST\n");
	exit();
}

$auth_state = VenusAuthStatus::PasswordRequired;

if (in_pairing_mode())
	$auth_state = VenusAuthStatus::Allowed;
else
	$auth_state = venus_authenticate_basic_auth();

if ($auth_state != VenusAuthStatus::Allowed && $auth_state != VenusAuthStatus::AllowedUnsecured) {
	http_response_code(403);
	exit();
}

$role = get_query_argument('role');
$device_id = get_query_argument('device_id');

$username = "token/$role/$device_id";
$password = generate_random_string(32);

$response = [
	'token_name' => $username,
	'password' => $password
];

$j = json_encode($response, JSON_UNESCAPED_SLASHES);

if ($j === false) {
	http_response_code(500);
	exit();
}

try {
	place_token_request($username, $password);
} catch (Exception $ex) {
	http_response_code(500);
	exit();
}

header('Content-Type: application/json');
print($j . "\n");

