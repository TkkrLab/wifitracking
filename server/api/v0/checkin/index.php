<?php

// required headers
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
 
// get database connection
include_once '../../../db.php';
 
// get posted data
$data = json_decode(file_get_contents("php://input"));

// dump to file for troubleshooting (remove from production)
$raw = var_export($data, true);
file_put_contents ("/home/florian/apps/wtr/server/log/wtr.log", $raw, FILE_APPEND);

// make sure data is not empty
if(
        !empty($data->node)
){
        $pdo = new PDO("mysql:host=".DBHOST.";dbname=".DBNAME, DBUSER, DBPASS);

        $sth = $pdo->prepare("SELECT * FROM nodes WHERE node=?");
        $sth->execute(array($data->node));
        if($sth->rowCount() == 1) {
                // Node already signed in, updating
                $result = $sth->fetch(PDO::FETCH_ASSOC);
                $nid = $result['nid'];
                $sth = $pdo->prepare("UPDATE nodes SET version=?, millis=?, lastseen=UNIX_TIMESTAMP('') WHERE nid=?");
                $sth->execute(array($data->version, $data->millis, $nid));

        } else {
                // New node reporting, signing in
                // A new node was found, lets create it
                $sth = $pdo->prepare("INSERT INTO nodes (node, version, millis) VALUES (?, ?, ?)");
                $sth->execute(array($data->node, $data->version, $data->millis));

        }

        // tell the user
        // set response code - 201 created
        http_response_code(201);
        echo json_encode(array("message" => "Checkin registered."));
}
 
// tell the user data is incomplete
else{
        // tell the user
        // set response code - 400 bad request
        http_response_code(400);
        echo json_encode(array("message" => "Unable to process. Data is incomplete."));
}
?>
