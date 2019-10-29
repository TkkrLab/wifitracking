<?php

// get database connection
include_once '../db.php';

header('Content-type: text/plain; charset=utf8', true);

function check_header($name, $value = false) {
    if(!isset($_SERVER[$name])) {
        return false;
    }
    if($value && $_SERVER[$name] != $value) {
        return false;
    }
    return true;
}

function sendFile($path) {
    header($_SERVER["SERVER_PROTOCOL"].' 200 OK', true, 200);
    header('Content-Type: application/octet-stream', true);
    header('Content-Disposition: attachment; filename='.basename($path));
    header('Content-Length: '.filesize($path), true);
    header('x-MD5: '.md5_file($path), true);
    readfile($path);
}

if(!check_header('HTTP_USER_AGENT', 'ESP8266-http-Update')) {
    header($_SERVER["SERVER_PROTOCOL"].' 403 Forbidden', true, 403);
    echo "Nothing to see here.\n";
    exit();
}

$logline = "Upgrade query by ";
$logline .= $_SERVER['HTTP_X_ESP8266_STA_MAC'] . "/" . $_SERVER['HTTP_X_ESP8266_AP_MAC'];
$logline .= " SDK " . $_SERVER['HTTP_X_ESP8266_SDK_VERSION'] . ",";
$logline .= " Free space " . $_SERVER['HTTP_X_ESP8266_FREE_SPACE'] . ",";
$logline .= " Sketch size " . $_SERVER['HTTP_X_ESP8266_SKETCH_SIZE'] . ",";
$logline .= " Chip size " . $_SERVER['HTTP_X_ESP8266_CHIP_SIZE'] . ",";
$logline .= " Version " . $_SERVER['HTTP_X_ESP8266_VERSION'] . "\n";

file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", $logline, FILE_APPEND);

if(
    !check_header('HTTP_X_ESP8266_STA_MAC') ||
    !check_header('HTTP_X_ESP8266_AP_MAC') ||
    !check_header('HTTP_X_ESP8266_FREE_SPACE') ||
    !check_header('HTTP_X_ESP8266_SKETCH_SIZE') ||
    !check_header('HTTP_X_ESP8266_CHIP_SIZE') ||
    !check_header('HTTP_X_ESP8266_SDK_VERSION') ||
    !check_header('HTTP_X_ESP8266_VERSION')
) {
    header($_SERVER["SERVER_PROTOCOL"].' 403 Forbidden', true, 403);
    file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Error: header missing\n", FILE_APPEND);
    echo "Nothing to see here.\n";
    exit();
}

// Split version string in nodename and catcher firmware version
$nodeversion = $_SERVER["HTTP_X_ESP8266_VERSION"];
$node = substr($nodeversion, 0, 15);
$version = substr($nodeversion, 17);
//file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Version breakdown: Node $node running firmware $version\n", FILE_APPEND);

if(substr($node, 0, 3) == "WTR") {
	// Okay, this ESP looks like it's with us...
	$pdo = new PDO("mysql:host=".DBHOST.";dbname=".DBNAME, DBUSER, DBPASS);

	$sth = $pdo->prepare("UPDATE nodes SET version=?, lastseen=UNIX_TIMESTAMP('') WHERE node=?");
	$sth->execute(array($version, $node));

	// Check for newer firmwares
	$dir = dir('.');
	while (false !== ($entry = $dir->read())) {
		//Ignore parent- and self-links
		if (($entry==".")||($entry=="..")) continue;

		// Check for .bin files with a version encoded in there
		if((substr($entry, 0, 10) == "WTRgeneric") && (substr($entry, -4) == ".bin")) {
			$newgenericversion = substr($entry,12,4);
			if(!isset($genericversion) || ($newgenericversion > $genericversion)) {
				$genericfirmware = $entry;
				$genericversion = substr($entry,12,4);
				file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Generic firmware $entry is version $genericversion\n", FILE_APPEND);
			}
		}
		if((substr($entry, 0, 15) == $node) && (substr($entry, -4) == ".bin")) {
			$newspecificversion = substr($entry,17,4);
			if(!isset($specificversion) || ($newspecificversion > $specificversion)) {
				$specificfirmware = $entry;
				$specificversion = substr($entry,17,4);
				file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Specific firmware $entry is version $specificversion\n", FILE_APPEND);
			}
		}
	}

	// Now determine if an upgrade is in order
	if(isset($specificversion) && $specificversion > $version) {
		file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Offering upgrade to specific firmware $specificfirmware\n", FILE_APPEND);
	        sendFile($specificfirmware);
	} elseif(isset($genericversion) && $genericversion > $version) {
		file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Should upgrade to generic firmware $genericfirmware\n", FILE_APPEND);
	        sendFile($genericfirmware);
	} else {
	        file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Already up to date\n", FILE_APPEND);
	        header($_SERVER["SERVER_PROTOCOL"].' 304 Not Modified', true, 304);
	}
	exit();
}

// Catchall: It looks like it might be an ESP8266, but we have no idea what it's running and why it is asking for firmware here.
file_put_contents ("/home/florian/apps/wtr/server/log/fw.log", "Unrecognised ESP chip, no code served\n", FILE_APPEND);
header($_SERVER["SERVER_PROTOCOL"].' 304 No code for you', true, 304);

