<?php

$page = isset($_GET["page"]) && $_GET["page"] != "" ? $_GET["page"] : "/";
require('session.php');
venus_session_start();
session_destroy();
http_response_code(303); // See Other
header('Location: ' . $page);
?>

