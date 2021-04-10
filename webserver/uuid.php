<?php




    $directoryName = 'd';
    if(!is_dir($directoryName)){
        mkdir($directoryName, 0755);
    }
    
    $directoryName = 'a';
    if(!is_dir($directoryName)){
        mkdir($directoryName, 0755);
    }
    
    function guidv4($data = null) {
        
        $guid = "";
        
        $done = false;
        $i = 0;
        while ($done == false) {
            
            $i++;
            if ($i == 10) {
                //echo "breaking";
                break;
            }
            
            // Generate 16 bytes (128 bits) of random data or use the data passed into the function.
            $data = $data ?? random_bytes(16);
            assert(strlen($data) == 16);

            // Set version to 0100
            $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
            // Set bits 6-7 to 10
            $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

            //$guid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
            $guid = vsprintf('%s-%s-%s', str_split(bin2hex($data), 4));
            
            $filename = 'd/' . $guid . '.json';
        
            if (!file_exists($filename)) {
                $done = true;
            }
            
        }
        
        return $guid;
    }

    $new_guid = guidv4();
    
    $file_name = 'd/' . $new_guid . '.json';
    $file = fopen($file_name, 'w') or die('Error opening file: '+$file_name);  
    fclose($file);  
    
    echo '{"uuid":"' . $new_guid . '"}';
    
    

?>