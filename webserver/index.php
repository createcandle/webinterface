<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="The WebThings Gateway is open source smart home software. It allows you to keep all your data under your control." />
    <meta name="author" content="CandleSmartHome.com" />
    
    <title>Web Interface</title>
    
    <script src="js/jquery-3.6.0.min.js"></script>
    <script src="js/lodash.min.js"></script>
    <script src="js/crypto-js.min.js"></script>
    <script src="js/aes256.js"></script>
    
    <link rel="stylesheet" href="main.css">
    
    <style>
        
    </style>
    
</head>
<body>
    <header>
        <div id="search-container">
            <input type="string" id="search" placeholder="search"/><button id="clear_search">x</button>
        </div>
        <h1>Web interface</h1>
    
        <form>
            <input type="string" id="uuid" name="uuid" placeholder="Anonymous ID" value=""/> <input type="password" id="password" name="password" placeholder="password" value=""/>
            <div id="remember_password_container">
                <input type="checkbox" name="remember_uuid" id="remember_uuid" checked /><label for="remember_uuid">Remember anonymous ID in this browser</label><br/>
                <input type="checkbox" name="remember_password" id="remember_password"/><label for="remember_password">Remember password in this browser</label>
            </div>
        </form>
        <p id="ten_seconds_warning" class="warning">After you enter the correct password it may take up to 10 seconds before data will show up.</p>
    </header>
    <div id="things"></div>


    <script>
        //console.log("crypto-js:");
        //console.log(CryptoJS);
        
        window.lasttime = 0;
        window.previous_things = {};
        window.things = {};

        window.remember_password = false;
        window.remember_uuid = true;
        
        window.recent_changes = [];
        
        
        if (localStorage.getItem('uuid') !== null) {
            console.log(`uuid exists`);
            
            if (localStorage.getItem('uuid') == 'ignore') {
                window.remember_uuid = false;
                $('#remember_uuid').prop('checked', false);
            }
        } else {
            console.log(`uuid not found`);
        }
        
        if (localStorage.getItem('pass') !== null) {
            console.log(`pass exists`);
            window.remember_password = true;
            $('#remember_password').prop('checked', true);
        } else {
            console.log(`pass not found`);
        }
        
        $(document).ready(function(){
            
            $.expr[":"].contains = $.expr.createPseudo(function(arg) {
                return function( elem ) {
                    return $(elem).text().toUpperCase().indexOf(arg.toUpperCase()) >= 0;
                };
            });
            
            // save password in browser checkbox
            $('#remember_password').change(function(event) {
                value = null;
                event.stopImmediatePropagation();
                event.stopPropagation();
                console.log(this);
            
                if( $(this).is(':checked') ){
                    console.log("checked");
                    const pass = $('#password').val();
                    window.remember_password = true;
                    localStorage.setItem('pass', pass);
                }
                else{
                    console.log("not checked");
                    window.remember_password = false;
                    //localStorage.setItem('hash', '');
                    localStorage.removeItem('pass');
                }
            });
            
            
            $("#search").on("input", function(){
                const search_text = $(this).val();
                console.log( search_text );
                
                if(search_text.length > 2 || search_text.length == 0){
                    search_filter();
                }
                
            });
            
            $('#clear_search').click(function() {
                $("#search").val("");
                search_filter();
            });
            
        });
        
        
        function search_filter(){
            const search_string = $('#search').val();
            const candidates = $('#things .thing');
            
            $('#things .thing').hide() // hide all the selected elements
            .filter(':contains(' + search_string  + ')')
            .show(); // show the filtered elements 
            
            /*
            $(candidates).find('h2:contains(' + search_string + ')').each(function(index){
            
                
            });
            */
        }
        
        
        function regenerate(things){
            console.log("in regenerate");
            console.log(window.things);
            
            $('#things').empty();
            
            if(window.things.length > 0){
                $('#ten_seconds_warning').hide();
                $('#search-container').slideDown();
            }
            else{
                $('#ten_seconds_warning').show();
                $('#search-container').hide();
            }
            
            console.log("window.recent_changes:");
            console.log(window.recent_changes);
            
            
            var d = new Date();
            const timestamp = d.getTime();
            console.log("checking for old ones with timestamp: " + timestamp);
            for (var i = window.recent_changes.length - 1; i >= 0; i--) {
                console.log(window.recent_changes[i]);
                const delta = (window.recent_changes[i]['timestamp'] + 20000) - timestamp;
                console.log("delta = " + delta);
                if( window.recent_changes[i]['timestamp'] + 20000 < timestamp ){
                    window.recent_changes.splice(i, 1);
                    console.log("removed old one");
                }
            }
            console.log("checking for old ones complete.");
            
            
            for (let i = 0; i < window.things.length; ++i) {
                //console.log(i);
                //console.log(window.things[i]);
            
                var thing_name = window.things[i].name;
                
                var thing = $("<div/>",{
                    "class" : "thing",
                    // .. you can go on and add properties
                    //"css" : {
                    //    "color" : "red"
                    //},
                    //"click" : function(){
                    //    console.log("you just clicked a thing");
                    //},
                    //"data" : {
                    //   "foo" : "bar"
                    //}
                });
                $(thing).html("<h2>" + window.things[i].title + "</h2>");
            
                var proplist = $("<div/>",{
                    "class" : "proplist"
                });
            
                $.each(window.things[i]['properties'], function(key,valueObj){
                    //console.log("key = " + key);
                    //console.log(valueObj);
                    var prop = $("<div/>",{
                        "class" : "property",
                        //"css" : {
                        //    "color" : "blue"
                        //},
                        //"click" : function(){
                        //    console.log("you just clicked a property");
                        //},
                        "data" : {
                           "id" : key
                        }
                    });
                
                    
                    // Label variables
                    var title = "Unknown";
                    if( valueObj.hasOwnProperty('title') ){
                        title = valueObj.title;
                    }
                    else if( valueObj.hasOwnProperty('label') ){
                        title = valueObj.label;
                    }
                    else if( valueObj.hasOwnProperty('name') ){
                        title = valueObj.name;
                    }
                    
                    var label_class_string = "";
                    if(valueObj.type == 'boolean'){
                        label_class_string += "webthing-switch-property-sliderx";
                    }
                    
                    $(prop).append('<label for="' + valueObj.name + '" class="' + label_class_string + '">' + title + '</label>');
                
                    
                    
                    var form = $("<div/>",{
                        "class" : "property-form",
                    });
                    

                    var type = valueObj.type;
                    var value = "";
                    var min = "";
                    var max = "";
                    
                    var checked = "";
                    var disabled = "";
                    var class_string="";
                    var url = "";
                    var multiple = "";
                    
                    if( valueObj.hasOwnProperty('multipleOf')){
                        multiple = ' data-multiple="' + valueObj.multipleOf + '"';
                    }
                    
                    if( valueObj.hasOwnProperty('links')){
                        for (let l = 0; l < valueObj.links.length; ++l) {
                            if(valueObj.links[l].rel == 'property'){
                                url = valueObj.links[0].href;
                            }
                        }
                    }

                    
                    for (var i = window.recent_changes.length - 1; i >= 0; i--) {
                        //console.log(window.recent_changes[i]);
                        if( window.recent_changes[i]['url'] == url ){
                            console.log("updating value: " + window.recent_changes[i]['value']);
                            valueObj.value = window.recent_changes[i]['value'];
                        }
                    }
                    
                    
                    
                    if(valueObj.readOnly == true){
                        disabled = " disabled ";
                    }
                    
                    if( valueObj.hasOwnProperty('enum') ){
                        //console.log("ENUM");
                        var select_element = '<select name="' + valueObj.name + '" data-url="' + url + '" data-id="' + valueObj.name + '" ' + disabled + '>';
                        //console.log($(select_element));
                        for (let j = 0; j < valueObj.enum.length; ++j) {
                            //console.log("adding option: " + valueObj.enum[j]);
                            var selected = "";
                            if( valueObj.enum[j] == valueObj.value ){
                                //console.log('selected option spotted');
                                selected = " selected ";
                            }
                            select_element += '<option value="' + valueObj.enum[j] + '" ' + selected + '>' + valueObj.enum[j] + '</option>';
                        }
                        select_element += '</select>';
                        $(form).append(select_element);
                        
                    }
                    else{
                       
                        if(valueObj.type == 'boolean'){
                            //class_string += "webthing-switch-property-switchx";
                            if(valueObj.value == true){
                                checked = " checked ";
                            }
                        }
                        else{
                            //console.log("value = " + valueObj.value);
                            if(valueObj.value != null && valueObj.value != 'null' && valueObj.value != 'undefined'){
                                value = ' value="' + valueObj.value + '" ';
                            }
                        }

                        if(valueObj.hasOwnProperty('minimum') && valueObj.hasOwnProperty('maximum')){
                            min = ' min="' + valueObj.minimum + '" ';
                            max = ' max="' + valueObj.maximum + '" ';
                            type = 'range';
                        }
                        else if(valueObj.type == 'boolean'){
                            type = 'checkbox';
                        }
                        else if(valueObj.type == 'string'){
                            if(valueObj.value == null || valueObj.value == 'null'){
                                value = "";
                            }
                            
                            if(valueObj.name == 'color' || valueObj['@type'] == 'ColorProperty'){
                                type = 'color';
                            }
                        }
                    
                        $(form).append('<input placeholder="?" type="' + type + '" class="' + class_string + '" name="' + valueObj.name + '" data-url="' + url + '" data-thing-id="' + thing_name + '" data-property-id="' + valueObj.name + '" ' + multiple + value + min + max + checked + disabled + '/>');
                        
                        if(type == 'range'){
                            $(form).append('<input placeholder="?" type="number" data-url="' + url + '" data-thing-id="' + thing_name + '" data-property-id="' + valueObj.name + '" ' + multiple + value + disabled + ' />');
                        }
                        
                        if(type == 'range' || type == 'number' || type == 'integer'){
                            $(form).append('<div class="math-buttons"><button class="math minus">-</button><button class="math plus" >+</button></div>');
                        }
                        
                    }
                    
                    $(form).appendTo($(prop));
                    
                    $(prop).appendTo($(proplist));
                });
            
                $(proplist).appendTo($(thing));
                
                
                //console.log("$(proplist).children().length = " + $(proplist).children().length );
                if( $(proplist).children().length > 0){
                    $(thing).appendTo("#things");
                }
            
            } // end of looping over all things.
            
            $('#things').change(function(event) {
                value = null;
                event.stopImmediatePropagation();
                event.stopPropagation();
                console.log(event);
                const url = event.target.dataset.url;
                var element = event.target;
                //console.log(element);
                var jel = $(element);
                
                if(event.target.type == 'checkbox'){
                    value = event.target.checked;
                }
                else{
                    value = jel.val();
                    console.log("typeof value: " + typeof value);
                    if(event.target.type == 'integer' || event.target.type == 'number' || event.target.type == 'range'){
                        console.log("source was a number");
                        value = parseFloat(value);
                    }
                    // quickly update range slider
                    if( isFinite(value) ){
                        //console.log("it was a number");
                        
                        if(element.nextSibling.nodeName == 'INPUT'){
                            
                            //console.log("next sibling was input");
                            var next_sibling = $(element.nextSibling);
                            next_sibling.val(value);
                        }
                        
                    }
                }
                
                const pass = get_pass();
                const hash = get_hash();
                //console.log("hash: " + hash);
                
                var action = {};
                action['url'] = url.toString();
                action['value'] = value;
                content = JSON.stringify(action);
                console.log("new action: " + content);
                const encrypted_content = AES256.encrypt(content, pass);
                
                
                add_recent_change(action['url'],value);
                
                $.ajax({
                    type: "POST",
                    url: "action.php",
                    data: { 'hash':hash, 'encrypted':encrypted_content },
                    cache: false,
                    success: function()
                        {
                            //console.log("time and password sent");
                        }
                    });                        
                
            });
            
            
            $('#things .math-buttons button').click(function(event) {
                console.log(event);
                const parent_element = $(event.target).parent().parent();
                
                var url = "";
                var value = "";
                
                var change_type = "plus";
                if( $(this).hasClass('minus') ){
                    change_type = "minus";
                }
                
                
                $(parent_element).find('input').each(function(index){
                    //console.log("change_type in each? = " + change_type);
                    //console.log( $(this) );
                    var math_change = $(this).data('multiple');
                    if( math_change === undefined){
                        console.log("multipleOf was undefined");
                        math_change = 1;
                    }
                    else{
                        math_change = parseFloat(math_change);
                    }
                    //console.log( $(this).data('multipla') );
                    //console.log("data-multiple = " + typeof math_change);
                    //console.log("data-multiple = " + math_change);
                    //console.log(typeof $(this).val());
                    var original_value = parseFloat($(this).val());
                    //console.log("original_value = " + original_value);
                    
                    if( change_type ==  'minus' ){
                        //console.log("- - -");
                        var total = original_value - math_change;
                    }
                    else{
                        //console.log("+ + +");
                        var total = original_value + math_change;
                    }
                    //console.log("total: " + total);
                    $(this).val( total );
                    value = total; // will be sent back to the home server
                    url = $(this).data('url');
                    
                    
                });
                
                add_recent_change(url,value);
                //console.log(parent_element);
                
                const pass = get_pass();
                const hash = get_hash();
                //console.log("hash: " + hash);
                
                var action = {};
                action['url'] = url.toString();
                action['value'] = value;
                content = JSON.stringify(action);
                console.log("will send action command: " + content);
                const encrypted_content = AES256.encrypt(content, pass);
                
                $.ajax({
                    type: "POST",
                    url: "action.php",
                    data: { 'hash':hash, 'encrypted':encrypted_content },
                    cache: false,
                    success: function()
                        {
                            //console.log("time and password sent");
                        }
                    });
            });
            
            search_filter();
            
        }
        
        
        
        // this function is run every 3 seconds
        function get_data(){
            const hash = get_hash();
            const uuid = get_uuid();
            const data_to_send = { hash: hash, uuid: uuid };
            
            //console.log(data_to_send);
            
            $.post( "loadjson.php", data_to_send, function( json ) {
                //console.log("loaded json:");
                //console.log( typeof json );
                console.log( json );
                
                if(json.hasOwnProperty('error')){
                    window.things = [];
                    regenerate();
                }
                else{
                    console.log("fresh: " + json['fresh']);
                    try{
                        if( json.fresh == true){
                        
                            const pass = get_pass();
                            const decrypted = AES256.decrypt(json.encrypted, pass);
                            decrypted_object = JSON.parse(decrypted);
                
                            if( ! _.isEqual(decrypted_object, window.things)){
                                console.log("The things data was different");
                                //window.previous_things = json.things;
                                window.things = decrypted_object;
                                regenerate();
                            }
                        }
                        else{
                            console.log("not fresh");
                        }
                    
                    }
                    catch(e){
                        console.log("Probably a decryption failure. Wrong password?: " + e);
                    }
                }
                
            //}, "json");
            });

        }
        
        
        setInterval(function(){ 
            console.log("3 second interval: grabbing thing data json");
            get_data();
        }, 3000);
        
        /*
        setInterval(function(){ 
            var d = new Date();
            window.lasttime = d.getTime();

            //const pass = $('#password').val();
            //console.log("pass = " + pass);
            
            const hash = get_hash();
            
            $.ajax({
                type: "POST",
                url: "lasttime.php",
                data: { 'time': window.lasttime,'hash': hash },
                cache: false,
                success: function()
                    {
                        //console.log("time and password sent");
                    }
                });
                
        }, 1000);
        */
        
        function add_recent_change(url,value){
            var d = new Date();
            const timestamp = d.getTime();
            
            console.log("Adding recent change. First checking if new change should override old one.");
            // remove old data if this property has already changed recently.
            for (var i = window.recent_changes.length - 1; i >= 0; i--) {
                console.log(window.recent_changes[i]);
                if( window.recent_changes[i]['url'] == url ){
                    console.log("MATCH!");
                    window.recent_changes.splice(i, 1);
                }
            }
            // Save the latest change
            window.recent_changes.push({"timestamp": timestamp, "url": url, "value": value});
            console.log("action added to recent changes list");
        }
        
        
        function get_pass() {
            var pass = $('#password').val();
            //console.log("pass val() = " + pass);
            if (pass == "" && localStorage.getItem('pass') !== null) {
                    console.log("pass input was empty, and localstorage was not empty, so getting pass from localstorage.");
                    pass = localStorage.getItem('pass');
                    $('#password').val(pass);
                
            }
            else if(pass != ""){
                //console.log("password input was not empty");
                if( window.remember_password){
                    localStorage.setItem('pass', pass);
                }
            }
            return pass;
        }
        
        function get_hash() {
            const pass = get_pass();
            return sha512(pass);
        }
        
        function get_uuid() {
            var uuid = $('#uuid').val();
            
            if (uuid == "" && localStorage.getItem('uuid') !== null) {
                console.log("uuid input was empty, and localstorage was not empty, so getting uuid from localstorage.");
                uuid = localStorage.getItem('uuid');
                $('#uuid').val(uuid);
                
            }
            else if(uuid != ""){
                //console.log("uuid input was not empty");
                if( window.remember_uuid){
                    localStorage.setItem('uuid', uuid);
                }
            }
            return uuid;
        }
        
        
        function sha512(str) {
            return CryptoJS.SHA512(str).toString(CryptoJS.enc.Hex);
        }
        
        
        
        
    </script>
</body>
</html>


