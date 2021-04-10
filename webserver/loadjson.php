<?php
    
    header('Content-Type: application/json');
    
    if( !isset($_POST["hash"]) || !isset($_POST["uuid"]) ){
    
        $postBody = '{"fresh":false,"error":"missing hash or uuid"}';
        
        $file = fopen($json_filename,'w');
                  fwrite($file, $postBody);
                  fclose($file);
        exit();
    }
    
    $hash = filter_var($_POST["hash"], FILTER_SANITIZE_STRING);
    $uuid = filter_var($_POST["uuid"], FILTER_SANITIZE_STRING);
    
    $uuid = str_replace("..", "", $uuid);
    $uuid = str_replace("/", "", $uuid);
    
    $json_filename = "d/" . $uuid . ".json";
    
    if (!file_exists($json_filename)) {
        echo '{"fresh":false, "error":"clear"}';
        exit();
    }
    $json = file_get_contents($json_filename);
    
    $data = json_decode($json, true);
    
    #$password = $_POST['password']; 
    #$hash = hash('sha512', $password);
    
    #echo $password;
    #echo "--\n";
    #echo $hash;
    #echo "--\n";
    #echo $data["hash"];
    #echo "\n";
    
    #$pingpong = fopen('hash.txt','w');
    #          fwrite($pingpong, $hash);
    #          fclose($pingpong);
    
    $date = new DateTime();
    $stamp = $date->getTimestamp();
    
    if($data["hash"] == $hash){
        #echo "requested hash and provided hash matched";
        echo $json;
        
    }
    else{
        echo '{"fresh":false,"error":"clear"}';
    }

    $postBody = '{"fresh":false ,"time":' . $stamp . ',"hash":"' . $hash . '"}';
    
    $file = fopen($json_filename,'w');
              fwrite($file, $postBody);
              fclose($file);

?>