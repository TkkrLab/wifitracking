<?php

// Wifi session expiration in seconds (300s = 5m)
define("EXPIRETIME", 300);

// required headers
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
 
// get database connection
include_once '../db.php';
 
// get posted data
$data = json_decode(file_get_contents("php://input"));
 
// make sure data is not empty
if(
	!empty($data->node) &&
	!empty($data->clients)
){
	$pdo = new PDO("mysql:host=".DBHOST.";dbname=".DBNAME, DBUSER, DBPASS);

	// retrieve node data (nid/lat/lon)
	$sth = $pdo->prepare("SELECT * FROM nodes WHERE node=?");
	$sth->execute(array($data->node));
	if($sth->rowCount() == 1) {
		$result = $sth->fetch(PDO::FETCH_ASSOC);
		$nid = $result['nid'];
		$lat = $result['lat'];
		$lon = $result['lon'];
	} else {
		$nid = 0;
		$lat = 0;
		$lon = 0;
	}

	// create or update client log for each client entry
	$clients = explode(",", $data->clients);
	foreach ($clients as $client) {
		echo $client;
		$sth = $pdo->prepare("SELECT * FROM sessions WHERE client=? AND nid=? AND (UNIX_TIMESTAMP()-UNIX_TIMESTAMP(stop) < ?)");
		$sth->execute(array($client, $nid, EXPIRETIME));
		if($sth->rowCount() == 0) {
			// No active session was found, start a new session
			echo " start new";
			$sth = $pdo->prepare("INSERT INTO sessions (client, nid, lat, lon) VALUES (?, ?, ?, ?)");
			$sth->execute(array($client, $nid, $lat, $lon));
		} else {
			// An active session was found, update it
			echo " kept alive";
			$result = $sth->fetch(PDO::FETCH_ASSOC);
			$sth = $pdo->prepare("UPDATE sessions SET stop=UNIX_TIMESTAMP('0000-00-00 00:00:00.000000') WHERE cid=?");
			$sth->execute(array($result["cid"]));
		}

	}

	// tell the user
	// set response code - 201 created
	http_response_code(201);
	echo json_encode(array("message" => "Clients registered."));
}
 
// tell the user data is incomplete
else{
	// tell the user
	// set response code - 400 bad request
	http_response_code(400);
	echo json_encode(array("message" => "Unable to process. Data is incomplete."));
}
?>
