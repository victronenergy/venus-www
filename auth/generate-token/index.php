<?php

/*
 * Allow to add a token by an authenticated user, for testing:
 * curl -k -v --user "remoteconsole:00000000" -d "role=test&device_id=test" https://xxx.xxx.xxx.xxx/auth/generate-token/
 */

require('../session.php');

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
	place_token_request_bcrypt(TOKENS_DIR, $username, $password);
} catch (Exception $ex) {
	http_response_code(500);
	exit();
}

header('Content-Type: application/json');
print($j . "\n");

