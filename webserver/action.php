<?php

#$json_filename = "actions.json";
#echo $_POST["password"];

if(!isset($_POST["hash"]) || !isset($_POST["encrypted"]) ){
    echo "missing inputs";
    exit();
}
else{
    echo "inputs are present<br/>";
}

$date = new DateTime();
$stamp = $date->getTimestamp();

#$time = intval($_POST['time']); 
$hash = $_POST['hash']; 
#$url = $_POST['url']; 
#$value = $_POST['value']; 
$encrypted = $_POST['encrypted']; 
#$hash = hash('sha512', $password);
#echo $time . "\n";
#echo $stamp . "\n";
echo $hash . "\n";
#echo $url . "\n";
#echo $value . "\n";
echo $encrypted  . "\n";

#$line = '{"timestamp":' . $stamp . ',"hash":"' . $hash . '","url":' . $url . ',"value":' . $value . ',"encrypted":' . $encrypted '},'; # . PHP_EOL;  
$line = '{"timestamp":' . $stamp . ',"hash":"' . $hash . '","encrypted":"' . $encrypted . '"},'; # . PHP_EOL;  

#file_put_contents('actions.txt', implode("\n", $gemList) . "\n", FILE_APPEND);
file_put_contents('actions.txt', $line, FILE_APPEND);


?>