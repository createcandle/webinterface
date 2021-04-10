<?php
header('Content-Type: application/javascript');
error_reporting(E_ERROR | E_PARSE);
 
// Set default timezone
date_default_timezone_set('UTC');

try {
    /**************************************
    * Create databases and                *
    * open connections                    *
    **************************************/

    // Create (connect to) SQLite database in file
    $file_db = new PDO('sqlite:mega2937622awesome.sqlite3');
    // Set errormode to exceptions
    $file_db->setAttribute(PDO::ATTR_ERRMODE,  PDO::ERRMODE_EXCEPTION);


    // Create new database in memory
    //$memory_db = new PDO('sqlite::memory:');
    // Set errormode to exceptions
    //$memory_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


    /**************************************
    * Create tables                       *
    **************************************/

    // Create table messages
    $file_db->exec("CREATE TABLE IF NOT EXISTS scores (
                    id INTEGER PRIMARY KEY,
                    uuid TEXT, 
                    terms SMALLINT, 
                    beauty SMALLINT,
					bmi SMALLINT,
                    closer SMALLINT, 
                    age SMALLINT, 
                    age_shared SMALLINT, 
					lied SMALLINT,
                    gender SMALLINT, 
                    clicker SMALLINT,
					clicker2 SMALLINT,
                    mouse INTEGER, 
					touch INTEGER, 
					life SMALLINT,
                    expression SMALLINT, 
                    end SMALLINT,
                    os TEXT)");

}
catch(PDOException $e) {
    // Print PDOException message
    echo $e->getMessage();
}  





if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {

    try{
        $post = $_POST;
        
        //echo $_POST['beauty'];
        //echo "-";

        foreach($post as $k => $v) {
            switch ($k) {
                case 'beauty':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    if($post[$k] == 0){
                        $post[$k] = null;
                    }
                    if($post[$k] > 100){
                        $post[$k] = 100;
                    }
                    if($post[$k] < 0){
                        $post[$k] = 0;
                    }
					
                    break;
	            case 'bmi':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    if($post[$k] == 0){
                        $post[$k] = null;
                    }
                    if($post[$k] < 14){
                        $post[$k] = 14;
                    }
                    if($post[$k] > 50){
                        $post[$k] = 38;
                    }
                    break;
                case 'gender':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'age':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    if($post[$k] < 0){
                        $post[$k] = 0;
                    }
                    if($post[$k] > 130){
                        $post[$k] = 130;
                    }
					break;
                case 'age_shared':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
					break;
	            case 'lied':
	                $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'mouse':
					if(is_null($v)){
						break;
					}
					
					try {
	                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
	                    
					}
					catch (exception $e) {
						$post[$k] = null;
					    break;
					}
                    if($post[$k] == 0){
                        $post[$k] = null;
                    }
					break;
	            case 'touch':
					try {
	                	$post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
		                break;
					}
					catch (exception $e) {
						$post[$k] = null;
					    break;
					}
		        case 'life':
					//echo "in life";
		            $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    if($post[$k] == 0){
                        $post[$k] = null;
                    }
		            break;
                case 'clicker':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;//filter_var($v, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                    break;
	            case 'clicker2':
	                $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;//filter_var($v, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
	                break;
                case 'aagje':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'terms':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'closer':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'expression':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'end':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_INT) * 1;
                    break;
                case 'os':
                    $post[$k] = filter_var($v, FILTER_SANITIZE_STRING);
                    break;
                //case 'float_2':
                //    $post[$k] = filter_var($v, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION) * 1;
                //    break;
                default:
                    break;
            }
        }
        if($post['end'] == 0){
            foreach($post as $k => $v) {
                $post[$k] = null;
            }
            $post['end'] = 0;
        }
        
        

        //echo $post['beauty'];
        
        /*
        function sani($value) {
            return htmlspecialchars(strip_tags($value));
        }
        */


        // Create table messages with different time format
        /*
        $memory_db->exec("CREATE TABLE messages (
                          id INTEGER PRIMARY KEY, 
                          title TEXT, 
                          message TEXT, 
                          time TEXT)");
        */

        /**************************************
        * Set initial data                    *
        **************************************/

        // Array with some test data to insert to database             
        /*
        $messages = array(
                      array('aagje' => 'Hello!',
                            'message' => 'Just testing...',
                            'time' => 1327301464),
                      array('title' => 'Hello again!',
                            'message' => 'More testing...',
                            'time' => 1339428612),
                      array('title' => 'Hi!',
                            'message' => 'SQLite3 is cool...',
                            'time' => 1327214268)
                    );
        */

        /**************************************
        * Play with databases and tables      *
        **************************************/

        // Prepare INSERT statement to SQLite3 file db
        $insert = "INSERT INTO scores (aagje, terms, beauty, bmi, closer, age, age_shared, lied, gender, clicker, clicker2, mouse, touch, life, os, expression, end) 
                    VALUES (:aagje, :terms, :beauty, :bmi, :closer, :age, :age_shared, :lied, :gender, :clicker, :clicker2, :mouse, :touch, :life, :os, :expression, :end)";
        $stmt = $file_db->prepare($insert);

        // Bind parameters to statement variables
        $stmt->bindParam(':aagje',  $post['aagje']);
        $stmt->bindParam(':terms',  $post['terms']);
        $stmt->bindParam(':beauty', $post['beauty']);
		$stmt->bindParam(':bmi', 	$post['bmi']);
        $stmt->bindParam(':closer', $post['closer']);
        $stmt->bindParam(':age',    $post['age']);
        $stmt->bindParam(':age_shared', $post['age_shared']);
		$stmt->bindParam(':lied',   $post['lied']);
        $stmt->bindParam(':gender', $post['gender']);
        $stmt->bindParam(':clicker',$post['clicker']);
		$stmt->bindParam(':clicker2',$post['clicker2']);
        $stmt->bindParam(':mouse',  $post['mouse']);
		$stmt->bindParam(':touch',  $post['touch']);
		$stmt->bindParam(':life',  	$post['life']);
        $stmt->bindParam(':os',     $post['os']);
        $stmt->bindParam(':expression', $post['expression']);
        $stmt->bindParam(':end',    $post['end']);

        $stmt->execute();
        // Loop thru all messages and execute prepared insert statement
    /*
        foreach ($messages as $m) {
          // Set values to bound variables
          $title = $m['title'];
          $message = $m['message'];
          $time = $m['time'];

          // Execute statement

        }
    */

          /*
        // Prepare INSERT statement to SQLite3 memory db
        $insert = "INSERT INTO messages (id, title, message, time) 
                    VALUES (:id, :title, :message, :time)";
        $stmt = $memory_db->prepare($insert);

        // Select all data from file db messages table 
        $result = $file_db->query('SELECT * FROM messages');

        // Loop thru all data from messages table 
        // and insert it to file db
        foreach ($result as $m) {
          // Bind values directly to statement variables
          $stmt->bindValue(':id', $m['id'], SQLITE3_INTEGER);
          $stmt->bindValue(':title', $m['title'], SQLITE3_TEXT);
          $stmt->bindValue(':message', $m['message'], SQLITE3_TEXT);

          // Format unix time to timestamp
          $formatted_time = date('Y-m-d H:i:s', $m['time']);
          $stmt->bindValue(':time', $formatted_time, SQLITE3_TEXT);

          // Execute statement
          $stmt->execute();
        }*/
        /*

        // Quote new title
        $new_title = $memory_db->quote("Hi''\'''\\\"\"!'\"");
        // Update old title to new title
        $update = "UPDATE messages SET title = {$new_title} 
                    WHERE datetime(time) > 
                    datetime('2012-06-01 15:48:07')";
        // Execute update
        $memory_db->exec($update);
        */

        
        // Select all data from memory db messages table 
        /*
        $result = $file_db->query('SELECT * FROM scores');

        foreach($result as $row) {
          echo "beauty: " . $row['beauty'] . "\n";
          echo "age: " . $row['age'] . "\n";
          echo "gender: " . $row['gender'] . "\n";
          echo "clicker: " . $row['clicker'] . "\n";
          echo "\n";
        }
        */

        //$return_array = json_encode($return_aray));
        //print_r($return_array);

        /**************************************
        * Drop tables                         *
        **************************************/

        // Drop table messages from file db
        //$file_db->exec("DROP TABLE messages");
        // Drop table messages from memory db
        //$memory_db->exec("DROP TABLE messages");


        /**************************************
        * Close db connections                *
        **************************************/


        // Close memory db connection
        //$memory_db = null;
    }
    catch(PDOException $e) {
        // Print PDOException message
        echo $e->getMessage();
    }
 
    
}
else{// GET
    

    //$result = $file_db->query('SELECT avg(age) FROM scores');
    //$result = $file_db->query('SELECT AVG(beauty),AVG(age),AVG(gender),AVG(mouse),AVG(clicker) AS avgBeauty,avgAge,avgGender,avgMouse,avgClicker FROM scores');
    $result = $file_db->query('SELECT AVG(terms),AVG(aagje),AVG(beauty),AVG(bmi),AVG(closer),AVG(age),AVG(age_shared),AVG(lied),AVG(gender),AVG(mouse),AVG(touch),AVG(life),AVG(clicker),AVG(clicker2),AVG(expression),AVG(end) FROM scores');
    
    $averages = $result->fetch();
    
	$full_ip_address = getUserIP();
	$ip_parts = explode(".", $full_ip_address, 3);

	$partial_ip_address = $ip_parts[0] . "." . $ip_parts[1];

    $done = array();
	
	$done['ip'] = $partial_ip_address;
	
    foreach ($averages as $key => $value) {
        //echo $key . " >>> " . $value . "     " ;
        $simple_name = str_replace("AVG(", "", $key);
        $simple_name = str_replace(")", "", $simple_name);

        if( (string)(int)$simple_name == !$simple_name) {
            $done[$simple_name] = $value;
        }
    }
    
	/*
	// Unused code to see if beautiful people have interesting correlations
    $result2 = $file_db->query('SELECT AVG(clicker) FROM scores WHERE beauty >= 60');
    
    $averages2 = $result2->fetch();
    $done['beauty_clicker_high'] = $averages2['AVG(clicker)'];
    
    
    $result3 = $file_db->query('SELECT AVG(clicker) FROM scores WHERE beauty < 60');
    
    $averages3 = $result3->fetch();
    $done['beauty_clicker_low'] = $averages3['AVG(clicker)'];
    */
	
    echo "const averages = "  .json_encode($done);

}



try{
    // Close file db connection
    $file_db = null;
}
catch(PDOException $e) {
    // Print PDOException message
    echo $e->getMessage();
}



function getUserIP()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];

    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    return $ip;
}

?>