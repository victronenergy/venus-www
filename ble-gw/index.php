<?php
/**
 * BLE Gateway to dbus-ble-sensors UDP forwarder
 *
 * Receives HTTP POST from Ruuvi Gateway or Shelly, extracts BLE advertisement data,
 * and forwards it to the dbus-ble-sensors UDP socket.
 */

error_reporting(0);
header('Content-Type: application/json');

define('UDP_HOST', '127.0.0.1');
define('UDP_PORT', 18542);

define('BLE_SOCKET_VERSION_V1', 0x01);
define('V1_FLAG_RSSI', 0x01);
define('V1_FLAG_REPEATER', 0x02);

define('BLE_SOCKET_VERSION_V2', 0x02);

// Security limits
define('MAX_INPUT_SIZE', 65536);		// 64KB max
define('MAX_TAGS_PER_REQUEST', 50);	 // Max sensors per request
define('MAX_ADV_DATA_SIZE', 512);	   // Max advertisement data size
define('MAX_ADV_DATA_SIZE_HEX', 1024);  // Max advertisement data size (hex encoded)
define('MAX_MFG_DATA_SIZE', 255);	   // Max manufacturer data (fits in uint8)
define('MIN_RSSI', -128);
define('MAX_RSSI', 126);

/**
 * Validate MAC address format
 */
function validate_mac(string $mac): bool
{
	return preg_match('/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/', $mac) === 1;
}

/**
 * Validate hex string
 */
function validate_hex(string $hex): bool
{
	return ctype_xdigit($hex) && strlen($hex) % 2 === 0;
}

/**
 * Convert MAC address string to bytes in bdaddr_t order (LSB first)
 */
function mac_to_bytes(string $mac): ?string
{
	if (!validate_mac($mac)) {
		return null;
	}

	$parts = array_map('hexdec', explode(':', $mac));
	if (count($parts) !== 6) {
		return null;
	}

	foreach ($parts as $byte) {
		if ($byte < 0 || $byte > 255) {
			return null;
		}
	}

	return pack('C6', ...array_reverse($parts));
}

/**
 * Build UDP packet for dbus-ble-sensors
 */
function build_packet_v2(
	string $sensor_mac,
	string $data,
	?int $rssi = null,
	?string $repeater_mac = null
): ?string
{
	if (strlen($data) > MAX_ADV_DATA_SIZE) {
		return null;
	}
	if ($rssi !== null && ($rssi < MIN_RSSI || $rssi > MAX_RSSI)) {
		return null;
	}

	$packet = pack('C', BLE_SOCKET_VERSION_V2);

	if ($repeater_mac !== null) {
		$repeater_mac_bytes = mac_to_bytes($repeater_mac);
		if ($repeater_mac_bytes === null) {
			return null;
		}
		$packet .= $repeater_mac_bytes;
	} else {
		$packet .= str_repeat("\x00", 6);
	}

	$sensor_mac_bytes = mac_to_bytes($sensor_mac);
	if ($sensor_mac_bytes === null) {
		return null;
	}
	$packet .= $sensor_mac_bytes;
	$packet .= pack('c', $rssi !== null ? $rssi : 0x7F);
	$packet .= $data;

	return $packet;
}

/**
 * Send UDP packet using fsockopen
 */
function send_udp(string $packet): bool
{
	$fp = @fsockopen('udp://' . UDP_HOST, UDP_PORT, $errno, $errstr, 1);
	if ($fp === false) {
		return false;
	}

	$result = fwrite($fp, $packet);
	fclose($fp);

	return $result !== false;
}

/**
 * Process incoming request
 */
function process_request(): void
{
	if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
		http_response_code(405);
		echo json_encode(['error' => 'Method not allowed']);
		return;
	}

	$content_type = $_SERVER['CONTENT_TYPE'] ?? '';
	if (strpos($content_type, 'application/json') === false) {
		http_response_code(415);
		echo json_encode(['error' => 'Content-Type must be application/json']);
		return;
	}

	$content_length = intval($_SERVER['CONTENT_LENGTH'] ?? 0);
	if ($content_length > MAX_INPUT_SIZE || $content_length === 0) {
		http_response_code(413);
		echo json_encode(['error' => 'Request too large or empty']);
		return;
	}

	$input = file_get_contents('php://input', false, null, 0, MAX_INPUT_SIZE);
	if ($input === false || strlen($input) === 0) {
		http_response_code(400);
		echo json_encode(['error' => 'Empty request body']);
		return;
	}

	$json = json_decode($input, true);
	if ($json === null || json_last_error() !== JSON_ERROR_NONE) {
		http_response_code(400);
		echo json_encode(['error' => 'Invalid JSON: ' . json_last_error_msg()]);
		return;
	}

	$data = $json['data'] ?? $json;

	$gw_mac = $data['gw_mac'] ?? null;
	if ($gw_mac !== null && !validate_mac($gw_mac)) {
		http_response_code(400);
		echo json_encode(['error' => 'Invalid gateway MAC address']);
		return;
	}

	$tags = $data['tags'] ?? null;
	if ($tags === null || !is_array($tags)) {
		http_response_code(400);
		echo json_encode(['error' => 'Missing or invalid tags array']);
		return;
	}

	if (count($tags) > MAX_TAGS_PER_REQUEST) {
		http_response_code(400);
		echo json_encode(['error' => 'Too many tags']);
		return;
	}

	$forwarded = 0;
	$errors = 0;
	$rejected = 0;

	foreach ($tags as $sensor_mac => $tag_data) {
		if (!is_string($sensor_mac)
			|| !validate_mac($sensor_mac)
			|| !is_array($tag_data)
		) {
			$errors++;
			continue;
		}

		$tag_data_data = $tag_data['data'] ?? null;
		if ($tag_data_data === null
			|| !is_string($tag_data_data)
			|| strlen($tag_data_data) > MAX_ADV_DATA_SIZE_HEX
			|| !validate_hex($tag_data_data))
		{
			$errors++;
			continue;
		}
		$decoded = hex2bin($tag_data_data);
		if ($decoded === false) {
			$errors++;
			continue;
		}

		$rssi = null;
		if (isset($tag_data['rssi']) && is_numeric($tag_data['rssi'])) {
			$rssi = intval($tag_data['rssi']);
		}

		$packet = build_packet_v2(
			$sensor_mac,
			$decoded,
			$rssi,
			$gw_mac
		);

		if ($packet === null) {
			$errors++;
			continue;
		}

		if (send_udp($packet)) {
			$forwarded++;
		} else {
			$errors++;
		}
	}

	http_response_code(200);
	echo json_encode([
		'status' => 'ok',
		'forwarded' => $forwarded,
		'errors' => $errors,
		'rejected' => $rejected
	]);
}

process_request();

?>
