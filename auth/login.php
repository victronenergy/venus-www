<?php

$page = isset($_GET["page"]) && $_GET["page"] != "" ? $_GET["page"] : "/";
$pwd_file = "/data/conf/vncpassword.txt";
$wrong_passwd = false;
$configured = file_exists($pwd_file);

/*
 * Implementation of a 'bucket with tokens' algorithm. Hard-coded to 10 initial tokens in the
 * bucket, re-fill one per second back to 10.
 */
function check_rate_limit() {
	$burst_limit = 10;
	$rate_limit_file="/tmp/php_auth_rate_limit_Z7iPAbefnKrmLITn.txt";
	$f = fopen($rate_limit_file, "c+");

	if ($f === false) {
		http_response_code(500); // Internal Server Error
		exit();
	}

	flock($f, LOCK_EX);

	$rate_state = [ 'last_attempt_at' => 0, 'tokens_left' => $burst_limit ];
	$serialized_data = trim(fgets($f));

	if ($serialized_data) {
		$unserialize_result = @unserialize($serialized_data);
		if ($unserialize_result !== false)
			$rate_state = $unserialize_result;
	}

	// First replenish tokens at one per sec.
	$seconds_diff = max(hrtime()[0] - $rate_state['last_attempt_at'], 0);
	$new_token_count = min($burst_limit, $seconds_diff + $rate_state['tokens_left']);
	$rate_state['tokens_left'] = $new_token_count;

	$allow = true;

	if ($rate_state['tokens_left'] > 0)
		$rate_state['tokens_left']--;
	else
		$allow = false;

	$rate_state['last_attempt_at'] = hrtime()[0];

	$new_serialized_data = serialize($rate_state);
	ftruncate($f, 0);
	fseek($f, 0);
	fwrite($f, $new_serialized_data);
	fclose($f);

	if (!$allow) {
		$sleep_time = random_int(500000, 1500000);
		usleep($sleep_time);

		http_response_code(429);
		exit();
	}
}

if ($configured) {
	$hash = @file_get_contents("/data/conf/vncpassword.txt");
	if ($hash === false) {
		http_response_code(500); // Internal Server Error
		exit();
	}

	$hash = trim($hash);
	if ($hash == "") {
		http_response_code(303); // See Other
		header("Location: " . $page);
		exit();
	}

	if (isset($_POST['password']))
		check_rate_limit();

	require('session.php');
	venus_session_start();

	if (isset($_POST['password'])) {
		if ($hash == "" || password_verify($_POST['password'], $hash)) {
			$_SESSION["remoteconsole-authenticated"] = true;

			http_response_code(303); // See Other
			header("Location: " . $page);
			exit();
		} else {
			$sleep_time = random_int(500000, 1500000);
			usleep($sleep_time);

			session_destroy();
			$wrong_passwd = true;
		}
	}
}

?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login</title>
		<link rel="stylesheet" href="styles.css">
	</head>
	<body>
	<?php if ($configured) { ?>
		<div class="outer_container auth">
			<img src="victron_logo.png" alt="Victron logo" class="victron_logo">
			<div class="inner_container auth">
				<div class="login">
					<h1 class="header">GX device login</h1>
					<form method="post">
						<input type="text" value="remoteconsole" name="username" id="username" autocomplete="username" style="display:none;">
						GX Password: <input type="password" name="password" id="password" autocomplete="new-password" required><BR>
						<?php if ($wrong_passwd) print("<span style='color: red'>Incorrect GX password</span>"); ?>
						<BR><BR>
						<input type="submit" class="continue" value="Login">
					</form>
				</div>
			</div>
		</div>
	<?php } else { ?>
		<div class="outer_container profile">
			<img src="victron_logo.png" alt="Victron logo" class="victron_logo">
			<div class="inner_container profile">
			<h3 class="header">A network security profile has not been selected</h3>
			<div class="note_body">
				<p>To access the GX via your web browser, first select a security profile.</p>
				<div class="instructions">
					<h4>There are 2 methods available:</h4>
					<ul>
						<li>Method 1: On the GX touch screen, navigate to Settings, General menu.</li>
						<li>Method 2: Using the VictronConnect App, connect with Bluetooth and there select the profile.</li>
					</ul>
				</div>
			</div>
		</div>
	<?php } ?>
	</body>
</html>

