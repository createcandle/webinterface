<?php
    
    
    if( !isset($_POST["hash"]) || !isset($_POST["uuid"]) ){
        #echo "missing hash and/or uuid and or data";
        #exit();
    }
    else{
        
        
        $hash = filter_var($_POST["hash"], FILTER_SANITIZE_STRING);
        $uuid = filter_var($_POST["uuid"], FILTER_SANITIZE_STRING);
        
        $uuid = str_replace("..", "", $uuid);
        $uuid = str_replace("/", "", $uuid);
        
        $filename = './a/' . $uuid . '.txt';
        
        $actions = file_get_contents($filename);
        
        /*
        echo "[";
             
        $separator = "\n";
        $line = strtok($actions, $separator);



        while ($line !== false) {
            # do something with $line
            $line = strtok( $separator );
            if( strpos( $line, $hash ) !== false) {
                echo $line . ",";
            }
        }
        echo '{"done":true}]';
        */
        
        if(substr($actions, -1) == ','){
            $actions = substr_replace($actions ,"",-1);
        }
    
        $actions = "[" . $actions . "]";
        echo $actions;
    
        #file_put_contents($filename, "");
    }
?>