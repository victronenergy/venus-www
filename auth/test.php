<?php

require('session.php');


if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
	$auth_status = venus_authenticate_basic_auth_with_token();
} else {
	$auth_status = venus_authenticate_session();
}

switch ($auth_status) {
case VenusAuthStatus::Allowed:
case VenusAuthStatus::AllowedUnsecured:
	http_response_code(200); // OK
	exit();
case VenusAuthStatus::PasswordRequired:
	http_response_code(401); // Authentication required
	exit();
case VenusAuthStatus::NotConfigured:
case VenusAuthStatus::WrongPassword:
	http_response_code(403); // Forbidden
	exit();
default:
	http_response_code(400); // Bad Request
	break;
}

