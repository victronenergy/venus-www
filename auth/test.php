<?php

$pwd_file = "/data/conf/vncpassword.txt";

// if the password file does not exists, authentication options are not yet configured
if (!file_exists($pwd_file)) {
	http_response_code(403); // Forbidden
	exit();
}

// Check if authentication is required.
$hash = @file_get_contents($pwd_file);
if ($hash === false) {
	http_response_code(500); // Internal Server Error
	exit();
}

if (trim($hash) == "") {
	http_response_code(200); // OK
	exit();
}

require('session.php');
venus_session_start();

if ($_GET["user"] == "remoteconsole") {
	if (isset($_SESSION["remoteconsole-authenticated"])) {
		http_response_code(200); // OK
		exit();
	} else {
		session_destroy();
		http_response_code(401); // Authentication required"
		exit();
	}
}

session_destroy();
http_response_code(400); // Bad Request

?>
