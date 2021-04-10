<?php
    
    #header('Content-Type: application/json');
    #echo $_POST["hash"];
    
    /*
    $post = file_get_contents('php://input');
    echo $post;
    
    
    if( isset($_POST["hash"]) ){
        echo "hash = " . $_POST["hash"];
    }
    if( isset($_POST["uuid"]) ){
        echo "uuid = " . $_POST["uuid"];
    }
    */
    
    
    if( !isset($_POST["hash"]) || !isset($_POST["uuid"]) ){
        echo '{"time":0,"error":"missing parameters"}';
    }
    else{
        //echo "both set";
        $hash = filter_var($_POST["hash"], FILTER_SANITIZE_STRING);
        $uuid = filter_var($_POST["uuid"], FILTER_SANITIZE_STRING);
        #$hash = hash('sha512', $password);
        
        $uuid = str_replace("..", "", $uuid);
        $uuid = str_replace("/", "", $uuid);
        
        $json_filename = "d/" . $uuid . ".json";
        
        if (file_exists($json_filename)) {
            $timejson = file_get_contents($json_filename);
            if($timejson == ""){
                echo '{"time":0,"error":"file was empty: ' . $json_filename . '"}';
            }
            else{
                echo $timejson;
            }
            
            #if( strpos($timejson,$hash) !== false) {
            #    echo $timejson;
            #}
            
        }else{
            echo '{"time":0,"error":"file did not exist: ' . $json_filename . '"}';
        }
        
    }
    /*
    else{
        echo '{"time":0,"error":"missing parameters"}';
        
    }
    */
    
?>