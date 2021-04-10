<?php

    header('Content-Type: application/json');
    
    
    
    if( !isset($_POST["hash"]) || !isset($_POST["encrypted"]) || !isset($_POST["uuid"]) || !isset($_POST["time"]) ){
        #echo "missing hash and/or uuid and or data";
        #exit();
        #$postBody = '{"error":"missing parameters"}';
        
        #$file = fopen($json_filename,'w');
        #          fwrite($file, $postBody);
        #          fclose($file);
    }
    else{
        
        #$date = new DateTime();
        #$stamp = $date->getTimestamp();
        
        #$postBody = file_get_contents("php://input");
        #$postBody = '{"hahahash":' . $_POST["hash"] . '}' . file_get_contents("php://input");
        #$uuid = $_POST["uuid"];
        
        
        $time = filter_var($_POST["time"], FILTER_SANITIZE_NUMBER_INT);
        $uuid = filter_var($_POST["uuid"], FILTER_SANITIZE_STRING);
        $hash = filter_var($_POST["hash"], FILTER_SANITIZE_STRING);
        $enc = filter_var($_POST["encrypted"], FILTER_SANITIZE_STRING);
        $postBody = '{"fresh":true, "time":' . $time . ', "hash":"' . $hash . '", "encrypted":"' . $_POST["encrypted"] .'"}';
        
        #$postBody = $_POST["encrypted"];
        $uuid = str_replace("..", "", $uuid);
        $uuid = str_replace("/", "", $uuid);
        
        $json_filename = "d/" . $uuid . ".json";
        
        $file = fopen($json_filename,'w');
                  fwrite($file, $postBody);
                  fclose($file);
    
        #$pingpong = fopen('pingpong.json','w');
        #          fwrite($pingpong, $stamp);
        #          fclose($pingpong);
    }
    
    
    

    
    /*
    sleep(10);
    
    # If the javascript hasn't loaded the data yet, delete it.
    
    $pingpong_state = file_get_contents('pingpong.json');
    if( $pingpong_state == $stamp ){
        # still the same timestamp as when the file was written, so it wasn't read by the javascript.
        if (!unlink($json_filename)) { 
            echo ("$json_filename cannot be deleted due to an error"); 
        } 
        else { 
            echo ("$json_filename has been deleted"); 
        } 
    }
    */
              
    
?>