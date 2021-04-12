<?php


    if( !isset($_POST["hash"]) || !isset($_POST["encrypted"]) || !isset($_POST["uuid"]) ){
        echo "missing hash and/or uuid and or data";
        exit();
    }
    else{
        $date = new DateTime();
        $stamp = $date->getTimestamp();

        $hash = filter_var($_POST["hash"], FILTER_SANITIZE_STRING);
        $uuid = filter_var($_POST["uuid"], FILTER_SANITIZE_STRING);
        $encrypted = filter_var($_POST["encrypted"], FILTER_SANITIZE_STRING);


        #$line = '{"timestamp":' . $stamp . ',"hash":"' . $hash . '","url":' . $url . ',"value":' . $value . ',"encrypted":' . $encrypted '},'; # . PHP_EOL;  
        $line = '{"time":' . $stamp . ',"hash":"' . $hash . '","encrypted":"' . $encrypted . '"},'; # . PHP_EOL;  

        $uuid = str_replace("..", "", $uuid);
        $uuid = str_replace("/", "", $uuid);
        
        $filename = './a/' . $uuid . '.txt';
        
        if (file_exists($filename)) {
             file_put_contents($filename, $line, FILE_APPEND);
        }

    }

?>