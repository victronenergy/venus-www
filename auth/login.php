<?php

$page = isset($_GET["page"]) && $_GET["page"] != "" ? $_GET["page"] : "/";
$pwd_file = "/data/conf/vncpassword.txt";
$wrong_passwd = false;
$configured = file_exists($pwd_file);

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

	require('session.php');
	venus_session_start();

	if (isset($_POST['password'])) {
		if ($hash == "" || password_verify($_POST['password'], $hash)) {
			$_SESSION["remoteconsole-authenticated"] = true;

			http_response_code(303); // See Other
			header("Location: " . $page);
			exit();
		} else {
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
		<title>Login</title>
		<link rel="stylesheet" href="styles.css">
	</head>
	<div class="outer_container auth">
		<img src="victron_logo.png" alt="Victron logo" class="victron_logo">
		<div class="inner_container auth">
			<?php if ($configured) { ?>
				<div class="login">
					<h1 class="header">Venus GX login</h1>
					<form method="post">
						<input type="text" value="remoteconsole" name="username" id="username" autocomplete="username" style="display:none;">
						Password: <input type="password" name="password" id="password" autocomplete="new-password" required><BR>
						<?php if ($wrong_passwd) print("<span style='color: red'>Incorrect password</span>"); ?>
						<BR><BR>
						<input type="submit" class="continue" value="Login">
					</form>
				</div>
			<?php } else { ?>
				<h1 class="header">A security profile has not been selected!</h1>
				A security profile can be selected on the display from the Settings -> General menu.
			<?php } ?>
		</div>
	</body>
</html>

