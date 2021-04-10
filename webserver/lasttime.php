<?php
    #$json_filename = "time.json";
    #echo $_POST["password"];
    
    header('Content-Type: application/json');
    
    if(!isset($_POST["hash"]) || !isset($_POST["time"])){
        echo "missing inputs";
        exit();
    }
    else{
        #echo "inputs are present<br/>";
    }
    
    $time = intval($_POST['time']);
    $time = filter_var($time, FILTER_SANITIZE_NUMBER_INT);
    $hash = filter_var($_POST["hash"], FILTER_SANITIZE_STRING);
    
    /*
    if(is_int($time)){
        $file = fopen("time.json",'w');
                  fwrite($file, json_encode( ['time' => $time, 'hash' => $hash ] ));
                  fclose($file);
    }
    */
    /*
    else{
        $file = fopen('error.txt','w');
                  fwrite($file, $time );
                  fclose($file);
    }
    */
    
    #$date = new DateTime();
    #$stamp = $date->getTimestamp();
    
    #$pingpong = fopen('pingpong.json','w');
    #          fwrite($pingpong, $stamp);
    #          fclose($pingpong);
    
    
?>