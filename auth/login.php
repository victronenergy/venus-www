<?php

require('session.php');

$page = isset($_GET["page"]) && $_GET["page"] != "" ? $_GET["page"] : "/";

$auth_status = venus_authenticate_session($_POST['password'] ?? null);

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
						<input type="text" value="remoteconsole" name="username" id="username" autocomplete="username" style="display:none;">
						GX Password: <input type="password" name="password" id="password" autocomplete="new-password" required><BR>
						<?php if ($auth_status === VenusAuthStatus::WrongPassword) print("<span style='color: red'>Incorrect GX password</span>"); ?>
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

