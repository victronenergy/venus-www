<?php

function read_password_hash() : string
{
	$hash = @file_get_contents("/data/conf/vncpassword.txt");
	if ($hash === false) 
	{
		http_response_code(500);
		print("Unexpected: Error reading password file.\n");
		exit();
	}

	$hash = trim($hash);
	return $hash;
}


function is_in_pair_mode() : bool
{
	return false;

	// TODO: check file that Jeroen / Platform will put somewhere.
}

function authorize_with_header() : bool
{
	$hash = read_password_hash();

	if (empty($hash))
		return true;

	$headers = getallheaders();
	$auth_header = $headers['Authorization'] ?? null;

	if (is_null($auth_header))
		return false;

	$fields = explode(' ', $auth_header);

	if (count($fields) != 2)
		return false;

	$b64_data = $fields[1];
	$username_password = base64_decode($b64_data);

	if ($username_password === false)
		return false;

	$cred_fields = explode(':', $username_password);

	if (count($cred_fields) != 2)
		return false;

	$password = $cred_fields[1];
	return password_verify($password, $hash);
}

function generate_random_string($length=32) {
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$charactersLength = strlen($characters);
	$randomString = '';
	for ($i = 0; $i < $length; $i++) 
	{
		$randomString .= $characters[random_int(0, $charactersLength - 1)];
	}
	return $randomString;
}

/*
 * Places a json file with the token to be added to the token database. Venus Platform 
 * will look at the watched dir and actually add them.
 *
 * The files are sortable and can be processed in order.
 *
 * Only watch for new_token__. The file will be given a temp name first.
 */
function place_token_request($token_name, $password) : void
{
	static $watched_dir = "/tmp/TODO_QUEUE";

	if (!is_dir($watched_dir))
		throw new Exception("Directory $watched_dir is not there.");

	if (!is_writable($watched_dir))
		throw new Exception("Directory $watched_dir is not writable.");

	$now = hrtime();
	$rnd_string = generate_random_string(5);
	$new_token_file_path = sprintf("$watched_dir/new_token__%010d.%010d.%s.json", $now[0], $now[1], $rnd_string);

	$tmp_path = tempnam($watched_dir, "tmp_new_token__");

	if ($tmp_path === false)
		throw new Exception("Can't create temp file for token generation");

	$user_data = array();
	$user_data['token_name'] = $token_name;
	$user_data['password_hash'] = password_hash($password, PASSWORD_BCRYPT);
	$new_json_text = json_encode($user_data, JSON_UNESCAPED_SLASHES);

	$tmp_file_handle = fopen($tmp_path, "w");

	if ($tmp_file_handle === false)
		throw new Exception("Can't open file for writing");

	$write_result = fwrite($tmp_file_handle, $new_json_text);
	fsync($tmp_file_handle);
	fclose($tmp_file_handle);

	if ($write_result === false)
	{
		unlink($tmp_path);
		throw new Exception("Failed to write new tokens file");
	}

	if (rename($tmp_path, $new_token_file_path) === false)
	{
		unlink($tmp_path);
	}
}

function get_query_argument(string $arg_name): ?string
{
	$val = $_POST[$arg_name] ?? $_GET[$arg_name] ?? null;

	if (empty($val))
	{
		http_response_code(400);
		print("POST argument $arg_name is required\n");
		exit();
	}

	if (preg_match("/^\w+$/", $val) !== 1)
	{
		http_response_code(400);
		print("$arg_name can only contain alpha-numerics.\n");
		exit();
	}

	return $val;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST')
{
	http_response_code(400);
	print("Method must be POST\n");
	exit();
}

$authorized = authorize_with_header() || is_in_pair_mode();

if (!$authorized)
{
	http_response_code(403);
	exit();
}

$role = get_query_argument('role');
$device_id = get_query_argument('device_id');

$username = "token/$role/$device_id";
$password = generate_random_string(32);

$response = array();
$response['token_name'] = $username;
$response['password'] = $password;

$j = json_encode($response, JSON_UNESCAPED_SLASHES);

if ($j === false)
{
	http_response_code(500);
	exit();
}

try
{
	place_token_request($username, $password);
}
catch (Exception $ex)
{
	http_response_code(500);
	exit();
}

print($j);
print("\n");



?>
