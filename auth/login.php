<?php

require('session.php');

$page = isset($_GET["page"]) && $_GET["page"] != "" ? $_GET["page"] : "/";

$info = null;
$auth_status = venus_authenticate_session($_POST['password'] ?? null, $info);

if ($auth_status == VenusAuthStatus::Allowed) {
	http_response_code(303); // See Other
	header("Location: " . $page);
	exit();
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
	<?php if ($auth_status !== VenusAuthStatus::NotConfigured) { ?>
		<div class="outer_container auth">
			<img src="victron_logo.png" alt="Victron logo" class="victron_logo">
			<div class="inner_container auth">
				<div class="login">
					<h1 class="header">GX device login</h1>
					<form method="post">
						<p><input type="text" value="remoteconsole" name="username" id="username" autocomplete="username" style="display:none;">
						GX Password: <input type="password" name="password" id="password" autocomplete="new-password" required></p>
						<?php
							if ($auth_status === VenusAuthStatus::WrongPassword)
								print("<p style='color: red'>Incorrect GX password</p>");

							if ($auth_status === VenusAuthStatus::WrongPassword || $auth_status === VenusAuthStatus::LockedOut) {
								$locked_duration = $info->lockedOutDuration();
								if ($locked_duration) {
									$hours = floor($locked_duration / 3600);
									$minutes = floor(($locked_duration % 3600) / 60);
									$seconds = $locked_duration % 60;
									$time = "{$hours}h {$minutes}m {$seconds}s";
									print("<p style='color: red'>Too many invalid login attempts. This device is locked for $time</p>");
								}
							}
						?>
						<p><input type="submit" class="continue" value="Login"></p>
					</form>
				</div>
			</div>
		</div>
		<script>
			// Focus on the password field when the page loads
			document.addEventListener("DOMContentLoaded", function() {
				document.getElementById("password").focus();
			});
		</script>
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
