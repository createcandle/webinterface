(function() {
  class Webinterface extends window.Extension {
    constructor() {
      	super('webinterface');
		//console.log("Adding webinterface addon to menu");
      	this.addMenuEntry('Web interface');

      	this.content = '';
        this.persistent_data = null;

        const jwt = localStorage.getItem('jwt');

        window.API.postJson(
          `/extensions/${this.id}/api/ajax`,
			{'action':'save_token','token':jwt}

        ).then((body) => {

        }).catch((e) => {
  			console.log("Error saving token: ", e);
        });

		fetch(`/extensions/${this.id}/views/content.html`)
        .then((res) => res.text())
        .then((text) => {
         	this.content = text;
			if( document.location.href.endsWith("extensions/webinterface") ){
				this.show();
			}
        })
        .catch((e) => console.error('Failed to fetch content:', e));
        
    }


    show() {
		//console.log("webinterface show called");
		
		if(this.content == ''){
			return;
		}
		else{
			this.view.innerHTML = this.content;
		}	
		
	  	

		const pre = document.getElementById('extension-webinterface-response-data');
		//const original = document.getElementById('extension-webinterface-original-item');
		//const list = document.getElementById('extension-webinterface-list');
		const view = document.getElementById('extension-webinterface-view'); 
		
		const leader_dropdown = document.querySelectorAll(' #extension-webinterface-view #extension-webinterface-original-item .extension-webinterface-thing1')[0];
		//const webinterface_dropdown = document.querySelectorAll(' #extension-webinterface-view #extension-webinterface-original-item .extension-webinterface-thing2')[0];
	
    
    
    
        var all_tabs = document.querySelectorAll('.extension-webinterface-tab');
        var all_tab_buttons = document.querySelectorAll('.extension-webinterface-main-tab-button');
        
        for(var i=0; i< all_tab_buttons.length;i++){
            all_tab_buttons[i].addEventListener('click', (event) => {
    			//console.log(event);
                var desired_tab = event.target.innerText.toLowerCase();
                //console.log("desired tab: " + desired_tab);
                if(desired_tab == '?'){desired_tab = 'help';}

                for(var j=0; j<all_tabs.length;j++){
                    all_tabs[j].classList.add('extension-webinterface-hidden');
                    all_tab_buttons[j].classList.remove('extension-webinterface-tab-selected');
                }
                document.querySelector('#extension-webinterface-tab-button-' + desired_tab).classList.add('extension-webinterface-tab-selected'); // show tab
                document.querySelector('#extension-webinterface-tab-' + desired_tab).classList.remove('extension-webinterface-hidden'); // show tab
            });
        };
    
    
		document.getElementById('extension-webinterface-outside-access').addEventListener('change', (event) => {
            //console.log("clicked allow-access button.");
            //console.log("allowed?: ", event.target.checked);
            
            window.API.postJson(
              `/extensions/${this.id}/api/ajax`,
    					    {'action':'outside_access', 'enabled':event.target.checked}

            ).then((body) => {
    			//console.log("Python API result:");
    			//console.log(body);
                
    			if(body['state'] == true){
                    //console.log("Settings was saved");
    			}
    			else{
    				alert("Error: unable to save the setting.");
    			}

            }).catch((e) => {
              	//pre.innerText = e.toString();
      			//console.log("webinterface: error in calling save via API handler");
      			//console.log(e.toString());
    			alert("Error: unable to save setting. Connection error?")
            });	
            
        });
       
        
    
		pre.innerText = "";
        
        
        // New UUID
		document.getElementById('extension-webinterface-new-uuid-button').addEventListener('click', (event) => {
			//console.log(event);
            if (confirm('Are you sure?')){
          		this.update_data('get_new_uuid');	
            }
        });
        
        
        // Show QR
        document.getElementById('extension-webinterface-show-qr-button').addEventListener('click', (event) => {
            document.getElementById('extension-webinterface-qrcode-container').style.display = 'block';
        });
        
        
        // Save password
        document.getElementById('extension-webinterface-save-password').addEventListener('click', (event) => {
			//console.log(event);
            //var target = event.currentTarget;
			//var parent3 = target.parentElement.parentElement.parentElement; //parent of "target"
			//parent3.classList.add("delete");
            
            const password1 = document.getElementById('extension-webinterface-password1').value;
            const password2 = document.getElementById('extension-webinterface-password2').value;
            
            if(password1 != password2){
                alert("The passwords did not match");
                return
            }
            
            if(password1.startsWith('12345')){
                alert("Oh come one, that's not secure");
                return
            }
            
            if(password1.length < 8){
                alert("The passwords needs to be at least 8 characters long");
                return
            }
            
            
            if (confirm('Are you sure you want to change the password?')){
          		
                //const hash = CryptoJS.SHA512(password1).toString(CryptoJS.enc.Hex);
                
                
                window.API.postJson(
                  `/extensions/${this.id}/api/ajax`,
                    {'action':'save_hash', 'password':password1} //  'hash':hash,

                ).then((body) => {
        			//console.log("Python API result:");
        			//console.log(body);
                    
        			if(body['state'] == true){
                        alert("The password was saved");
        			}
        			else{
        				//console.log("not ok response while getting data");
        				alert("Error: could not save password");
        			}

                }).catch((e) => {
                  	//pre.innerText = e.toString();
          			//console.log("webinterface: error in calling save via API handler");
          			//console.log(e.toString());
        			pre.innerText = "password save failed - connection error";
                });	
                
            }
      		
        });
        
        
        document.getElementById('extension-webinterface-thing-list-save-button').addEventListener('click', (event) => {
            //console.log('save');
            var checkboxes = document.querySelectorAll('#extension-webinterface-thing-list input');
            
            if(checkboxes.length > 0){
                var allowed_things = [];
                for (var t=0; t < checkboxes.length; t++) {
                    if(checkboxes[t].checked){
                        allowed_things.push(checkboxes[t].value);
                    }
                }
                //console.log("allowed_things: ", allowed_things);
                
                window.API.postJson(
                  `/extensions/${this.id}/api/ajax`,
        					    {'action':'save_allowed', 'allowed_things':allowed_things}

                ).then((body) => {
        			//console.log("Python API result:");
        			//console.log(body);
                    alert("Saved succesfully");

                }).catch((e) => {
                  	//pre.innerText = e.toString();
          			console.log("webinterface: error saving: ", e);
          			//console.log(e.toString());
                    alert("Could not save. Connection error?");
                });	
                
            }
            else{
                //console.log('no checkboxes in the list container?');
            }
            
        });
        
        
        
        //
        //  MATRIX
        //
        document.getElementById('extension-webinterface-matrix-create-account-button').addEventListener('click', (event) => {
            console.log("create matrix account button clicked");
            
            const server = document.getElementById('extension-webinterface-matrix-server').value;
            const username = document.getElementById('extension-webinterface-matrix-username').value;
            const password1 = document.getElementById('extension-webinterface-matrix-password1').value;
            const password2 = document.getElementById('extension-webinterface-matrix-password2').value;
            
            
            if(password1 != password2){
                alert("The passwords did not match");
                return
            }
            
            if(password1.startsWith('12345')){
                alert("Oh come one, that's not secure");
                return
            }
            
            if(password1.length < 8){
                alert("The passwords needs to be at least 8 characters long");
                return
            }
            
            
            console.log("server: ", server);
            console.log("username: ", username);
            console.log("password: ", password1);
            
            window.API.postJson(
              `/extensions/${this.id}/api/ajax`,
                {'action':'create_matrix_account', 
                'matrix_server':server,
                'matrix_username',username,
                'matrix_password':password1}

            ).then((body) => {
    			console.log("Python API create matrix account result: ", body);
                
    			if(body['state'] == true){
                    alert("The account was created succesfully");
    			}
    			else{
    				//console.log("not ok response while getting data");
    				alert("Error creating new Matrix account");
    			}

            }).catch((e) => {
              	//pre.innerText = e.toString();
      			//console.log("webinterface: error in calling save via API handler");
      			//console.log(e.toString());
                console.log('error connecting while trying to create Matrix account: ', e);
                alert("creating Matrix account failed - connection error");
    			//pre.innerText = "creating Matrix account failed - connection error";
            });	
            
            
            
            
            
        });
        
        
        
        
        
        
        
        this.update_data('init');

	}
	
    
    
	update_data(action){
        
        const pre = document.getElementById('extension-webinterface-response-data');
        
        window.API.postJson(
          `/extensions/${this.id}/api/ajax`,
					    {'action':action}

        ).then((body) => {
			//console.log("Python API result:");
			//console.log(body);


			if(body['state'] == true){
				this.persistent_data = body['persistent_data'];
				//this.regenerate_items();
                
                const qr_url = body['web_url'] + '?' + body['persistent_data']['uuid'];
                
                document.getElementById('extension-webinterface-uuid').value = body['persistent_data']['uuid'];
                document.getElementById('extension-webinterface-web-url').innerText = body['web_url'];
                document.getElementById('extension-webinterface-web-url-button').href = qr_url;
                
                
                
                const target_element = document.getElementById('extension-webinterface-qrcode');
            	//console.log("target_element:");
            	//console.log(target_element);

                //console.log(QRCode);

            	var qrcode = new QRCode(target_element, {
            		width : 300,
            		height : 300
            	});
            	qrcode.makeCode(qr_url);
                
                if(action == 'init'){
                    //console.log('init response');
                    
                    if(typeof body.persistent_data != 'undefined'){
                        if(typeof body.persistent_data.enabled != 'undefined'){
                            document.getElementById('extension-webinterface-outside-access').checked = body.persistent_data.enabled;
                        }
                    }
                    
                    
                    
                    const thing_list = document.getElementById('extension-webinterface-thing-list');
                    
                    if(body.things.length == 0){
                        thing_list.innerHTML = '<div style="background-color:rgba(0,0,0,.2);padding:2rem"><h3>There are no things to display?</h3><p>Either you have no things, or you have not granted this addon permission to access your things yet. To do so, open the Candle app store and visit the settings page of this addon. There you can grant permission.</p></div>';
                    }
                    else{
                        thing_list.innerHTML = "";
                    
                        body.things.sort((a, b) => (a.name.toLowerCase() > b.name.toLowerCase()) ? 1 : -1) // sort alphabetically
                    
        				// Loop over all items
        				for( var index in body.things ){
    					    try{
                                const item = body.things[index];
                                //console.log("item: ", item);
            					//var clone = original.cloneNode(true);
            					//clone.removeAttribute('id');
                    
                                //var station_name = "Error";
                                //var stream_url = "Error";
                                var container = checkbox = document.createElement('div');
                                container.classList.add('extension-webinterface-item')
                        
                                var checkbox = document.createElement('input');
                                checkbox.type = "checkbox";
                                checkbox.name = item.name;
                                checkbox.id = item.name;
                                checkbox.value = item.name;
                                //checkbox.id = "id";
                                if(typeof body.persistent_data.allowed_things != 'undefined'){
                                    if( body.persistent_data.allowed_things.indexOf(item.name) > -1){
                                        checkbox.checked = true;
                                    }
                                }
                                var label = document.createElement('label');
                                label.htmlFor = item.name;
                                //label.appendChild(checkbox);
                                label.appendChild(document.createTextNode(item.title));
                            
                                container.appendChild(checkbox);
                                container.appendChild(label);
                        
                                thing_list.appendChild(container);
    					    }
                            catch(e){
                                //console.log("Error generating an item: ", e);
                            }
                            
                        }
                        document.getElementById('extension-webinterface-thing-list-button-container').style.display = 'block';
                    }
                    
                
                }
                
                
                
			}
			else{
				//console.log("not ok response while getting data");
				//pre.innerText = body['message'];
			}
            

        }).catch((e) => {
          	//pre.innerText = e.toString();
  			//console.log("webinterface: error in calling init via API handler");
  			//console.log(e.toString());
			pre.innerText = "Loading items failed - connection error";
        });	
	}
	




	//
	//  A helper method that generates nice lists of properties from a Gateway property dictionary
	//
	get_property_lists(properties){
		//console.log("checking properties on:");
		//console.log(properties);
		var property1_list = []; // list of user friendly titles
		var property1_system_list = []; // list internal property id's
		
		for (let prop in properties){
			//console.log(properties[prop]);
			var title = 'unknown';
			if( properties[prop].hasOwnProperty('title') ){
				title = properties[prop]['title'];
			}
			else if( properties[prop].hasOwnProperty('label') ){
				title = properties[prop]['label'];
			}
				
			
			var system_title = properties[prop]['links'][0]['href'].substr(properties[prop]['links'][0]['href'].lastIndexOf('/') + 1);

			// If a property is a number, add it to the list of possible source properties
			if( properties[prop]['type'] == 'integer' || properties[prop]['type'] == 'float' || properties[prop]['type'] == 'number' || properties[prop]['type'] == 'boolean'){
				
				property1_list.push(title);
				property1_system_list.push(system_title);

			}
		}
		
		return { 'property1_list' : property1_list, 'property1_system_list' : property1_system_list };
	}
    
    
    
	
  }

  new Webinterface();
	
})();

