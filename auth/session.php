<?php

function venus_session_start($readonly = false)
{
	session_start([
		'cookie_lifetime' => 365 * 24 * 60 * 60,
		'read_and_close'  => $readonly,
		'name' => 'VENUS_SESSION_ID',
		'save_path' => '/data/var/lib/venus-www-sessions'
	]);
}

?>
