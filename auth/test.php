<?php

require('session.php');

$auth_status = venus_authenticate_session();

switch ($auth_status) {
case VenusAuthStatus::Allowed:
case VenusAuthStatus::AllowedUnsecured:
	http_response_code(200); // OK
	exit();
case VenusAuthStatus::PasswordRequired:
	http_response_code(401); // Authentication required
	exit();
case VenusAuthStatus::NotConfigured:
	http_response_code(403); // Forbidden
	exit();
default:
	http_response_code(400); // Bad Request
	break;
}

