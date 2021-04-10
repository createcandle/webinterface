"""Webinterface API handler."""


import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
import json
import time
from time import sleep
import uuid
import base64
import requests
from passlib.hash import pbkdf2_sha512
import hashlib
import threading
from AesEverywhere import aes256


try:
    from gateway_addon import APIHandler, APIResponse, Adapter, Device, Property, Database
    #print("succesfully loaded APIHandler and APIResponse from gateway_addon")
except:
    print("Import APIHandler and APIResponse from gateway_addon failed. Use at least WebThings Gateway version 0.10")
    sys.exit(1)



_TIMEOUT = 3

_CONFIG_PATHS = [
    os.path.join(os.path.expanduser('~'), '.webthings', 'config'),
]

if 'WEBTHINGS_HOME' in os.environ:
    _CONFIG_PATHS.insert(0, os.path.join(os.environ['WEBTHINGS_HOME'], 'config'))



class WebinterfaceAPIHandler(APIHandler):
    """Webinterface API handler."""

    def __init__(self, verbose=False):
        """Initialize the object."""
        #print("INSIDE API HANDLER INIT")
        
        
        self.addon_name = 'webinterface'
        self.running = True

        self.server = 'http://127.0.0.1:8080'
        self.DEV = True
        self.DEBUG = False
            
        self.things = [] # Holds all the things, updated via the API. Used to display a nicer thing name instead of the technical internal ID.
        self.data_types_lookup_table = {}
        self.token = None
        self.password = None
        self.web_url = ""
        self.uuid = ""

        self.total_time_delta = 0
        self.previous_enabled_state = False

        # LOAD CONFIG
        try:
            self.add_from_config()
        except Exception as ex:
            print("Error loading config: " + str(ex))

        #print("self.token = " + str(self.token))
        #print("self.password = " + str(self.password))
        
        self.hash = str( hashlib.sha512( bytes(self.password, 'utf-8') ).hexdigest() )
        # Get complete things dictionary via API
        
        
        
        
        # Paths
        # Get persistent data
        try:
            #print("self.user_profile['dataDir'] = " + str(self.user_profile))
            self.persistence_file_path = os.path.join(self.user_profile['dataDir'], self.addon_name, 'persistence.json')
        except:
            try:
                if self.DEBUG:
                    print("setting persistence file path failed, will try older method.")
                self.persistence_file_path = os.path.join(os.path.expanduser('~'), '.webthings', 'data', self.addon_name,'persistence.json')
            except:
                if self.DEBUG:
                    print("Double error making persistence file path")
                self.persistence_file_path = "/home/pi/.webthings/data/" + self.addon_name + "/persistence.json"
        
        if self.DEBUG:
            print("Current working directory: " + str(os.getcwd()))
        
        
        first_run = False
        try:
            with open(self.persistence_file_path) as f:
                self.persistent_data = json.load(f)
                if self.DEBUG:
                    print("Persistence data was loaded succesfully.")
                
        except:
            first_run = True
            print("Could not load persistent data (if you just installed the add-on then this is normal)")
            self.persistent_data = {"uuid":"","active":True}
            
        if self.DEBUG:
            print("Webinterface self.persistent_data is now: " + str(self.persistent_data))


        try:
            self.adapter = WebinterfaceAdapter(self,verbose=False)
            #self.manager_proxy.add_api_handler(self.extension)
            print("ADAPTER created")
            pass
        except Exception as ex:
            print("Failed to start ADAPTER. Error: " + str(ex))
            
            
        if self.persistent_data['uuid'] == "":
            a = requests.get('https://www.candlesmarthome.com/webinterface/uuid.php')
            #print("actions data: " + str(a.content))
            uuid_json = a.json()
            print(str(uuid_json))
            self.persistent_data['uuid'] = uuid_json['uuid']
            self.save_persistent_data()
            
        if 'enabled' not in self.persistent_data:
            self.persistent_data['enabled'] = True
            self.save_persistent_data()
            
            
        # Intiate extension addon API handler
        try:
            manifest_fname = os.path.join(
                os.path.dirname(__file__),
                '..',
                'manifest.json'
            )
            print(str(manifest_fname))
            with open(manifest_fname, 'rt') as f:
                manifest = json.load(f)

            print("manifest['id'] = " + str(manifest['id']))
            
            APIHandler.__init__(self, manifest['id'])
            self.manager_proxy.add_api_handler(self)

            #if self.DEBUG:
            #    print("self.manager_proxy = " + str(self.manager_proxy))
            #    print("Created new API HANDLER: " + str(manifest['id']))
        
        except Exception as e:
            print("Failed to init UX extension API handler: " + str(e))
        

        # Start the internal clock
        #if self.DEBUG:
        #    print("Starting the internal clock")
        try:      
            if self.token != None and self.password != None:      
                t = threading.Thread(target=self.clock)
                t.daemon = True
                t.start()
                #pass
        except:
            print("Error starting the clock thread")




    # Read the settings from the add-on settings page
    def add_from_config(self):
        """Attempt to read config data."""
        try:
            database = Database(self.addon_name)
            if not database.open():
                print("Could not open settings database")
                return
            
            config = database.load_config()
            
            if config:
                print("config loaded")
                if 'Anonymous ID' in config:
                    if str(config['Anonymous ID']) == "" and str(self.persistent_data['uuid']) != "":
                        config['Anonymous ID'] = str(self.persistent_data['uuid'])
                        database.save_config(config)
                        
            database.close()
            
        except:
            print("Error! Failed to open settings database.")
        
        
        if not config:
            print("Error loading config from database")
            return
        
        
        
        # Api token
        try:
            if 'Authorization token' in config:
                self.token = str(config['Authorization token'])
                print("-Authorization token is present in the config data.")
        except:
            print("Error loading api token from settings")
        
        # Password
        try:
            if 'Password' in config:
                self.password = str(config['Password'])
                print("-Password is present in the config data.")
        except:
            print("Error loading password from settings")
            
            
        # Web url
        try:
            if 'Web location' in config:
                self.web_url = str(config['Web location'])
                if not self.web_url.endswith("/"):
                    self.web_url += "/"
                print("-Web location is present in the config data.")
        except:
            print("Error loading web location from settings")
        
        
        # Debugging
        if 'Debugging' in config:
            self.DEBUG = bool(config['Debugging'])
            if self.DEBUG:
                print("-Debugging preference was in config: " + str(self.DEBUG))







#
#  CLOCK
#

    def clock(self):
        """ Runs every second """
        seconds_counter = 0
        while self.running:
            time.sleep(1)
            #print(".")
            seconds_counter += 1
            if seconds_counter >= 5:
                seconds_counter = 0
            try:
                if self.persistent_data['enabled']:
                    self.previous_enabled_state = True
                    #print("Did the things API call. Self.things is now:")
                    #print(str(self.things))
                    print(str(seconds_counter))
                    #print(str( self.web_url + "gettime.php" ))
                
                    parameters = {"fresh":False,"hash": self.hash, "uuid": self.persistent_data['uuid'] }
                    print("sending: " + str(parameters))
                    q = requests.post( self.web_url + "gettime.php", data = parameters)
                    #print("q.content = " + str(q.content))
                    timejson = q.json()
                    #print("timejson = " + str(timejson))
                    #print("loading json via loads")
                    #timejson = json.loads( timejson )
                
                    #print(str(timejson))
                    #print(str(time.time()))
                    if 'time' in timejson:
                        print(str(timejson['time']))
                        time_delta = abs( time.time() - ( timejson['time'] ) ) # / 1000
                        self.total_time_delta += time_delta
                        print("time delta: " + str( time_delta ) )
                        print("total time delta: " + str( self.total_time_delta ) )
                        #print("")
                        #print("timejson password = " + str(timejson['password']))
                        #print("self.hash passwrd = " + str(self.hash))
                        if time_delta < 15:
                            if 'hash' in timejson:
                                if self.hash == str(timejson['hash']):
                                    #print("hash == hash, and time is ok too.")
                    
                                    # First, check if there are any actions that need to be performed buffered on the server.
                                    try:
                                        a = requests.post(self.web_url + 'get_actions.php', data={"hash":self.hash, "uuid":self.persistent_data['uuid'] })
                                        print("actions data: " + str(a.content))
                                        messages = a.json()
                                        #print(str("message json: " + str(messages))) 
                                        #print(aes256.decrypt(encrypted, self.hash))
                                        for message in messages:
                                            if 'encrypted' in message:
                                                encrypted = message['encrypted']
                                                #print("action encrypted = " + str(encrypted))
                                                decrypted = aes256.decrypt(encrypted, self.password)
                                                #print("actions decrypted = " + str(decrypted))
                                                action = json.loads( decrypted )
                                                #print("action dict: " + str(action))
                                                #for action in actions:
                                                #print("action url: " + str(action['url']))
                                                #print("action value: " + str(action['value']))
                                                #print("action: " + str(action))
                            
                                                prop_id = os.path.basename(os.path.normpath( action['url'] ))
                                                #print("prop_id = " + str(prop_id))
                                                #print("action['value'] = " + str(action['value']))
                                                data_to_put = { str(prop_id) : action['value'] }
                                                #print("data_to_put = " + str(data_to_put))
                                                api_put_result = self.api_put( action['url'], data_to_put )
                                    except Exception as ex:
                                        print("Error getting or handling latest action messages: " + str(ex))
                            
                                            #if self.hash == str(action['hash']):
                                            #    print("GOOD HASH")
                                
            
                                    time.sleep(.1)
                                    if self.total_time_delta > 5:
                                        self.total_time_delta = 0
                                        if self.DEBUG:
                                            print("Password ok, and some time has passed. Posting to web")
                                        self.things = self.api_get("/things")
                                        #testje = self.api_get("/things/internet-radio/properties/power")
                                        #station = self.api_get("/things/internet-radio/properties/station")
                                        #radio = self.api_get("/things/internet-radio")
                                        #print("radio power: " + str(testje))
                                        #print("radio station: " + str(station))
                                        #print("radio: " + str(radio))
            
                                        if '{"error":401}' in self.things:
                                            if self.DEBUG:
                                                print("401 ERROR - token missing?")
                                        else:
                                            #print("")
                                            #print("__THINGS__")
                                            #print("")
                                            #print(str(self.things))
                                            self.update_things() # this goes over every property and gets the actual latest value
                                            #print("")
                                            #print("")
                            
                                            things_string = json.dumps(self.things)
                                            encrypted_string = aes256.encrypt(things_string, self.password)
                                            #encoded_string = encrypted_string.decode('utf-8')
                                            #print("encrypted string: ")
                                            #print(str(encrypted_string.decode('utf-8')))
                            
                                            decoded_base64_string = base64.b64decode(encrypted_string)
                                            #print("decoded_base64_string:")
                                            #print(str(decoded_base64_string))
                            
                                            base64_string = base64.b64encode(encrypted_string) # .encode('utf-8')  # .decode('UTF-8')
                                            decoded_string = base64_string.decode('utf-8')
                                            #print("decoded base64 string:")
                                            #print(decoded_string)
                                
                                            r = requests.post(self.web_url + 'receiver.php', data={"hash":self.hash, "uuid":self.persistent_data['uuid'], "time":time.time(), "encrypted":encrypted_string.decode('utf-8') }) # json={"hash":self.hash,"encrypted": encrypted_string.decode('utf-8')})
                    
                                else:
                                    if self.DEBUG:
                                        print("passwords did not match")
                                    if seconds_counter == 0:
                                        r = requests.post(self.web_url + 'receiver.php', data={"hash":self.hash, "time":0 })
                    
                        # if time_delta > 15 seconds
                        else:
                            r = requests.post(self.web_url + 'receiver.php', data={"hash":self.hash, "time":0 })
                 
                else:
                    if self.previous_enabled_state == True:
                        # Delete all data on the webserver.
                        r = requests.post(self.web_url + 'receiver.php', data={"hash":self.hash, "time":0 })
                        a = requests.post(self.web_url + 'get_actions.php', data={"hash":self.hash, "uuid":self.persistent_data['uuid'] })
                        self.previous_enabled_state = False
                
            except Exception as ex:
                print("Clock: error preparing updated things data: " + str(ex))
                        
                        

    # The api request to /things doesn't serve the latest data somehow. This fixes that.
    def update_things(self):
        #print("in update things")
        try:
            thing_counter = 0
            prop_counter = 0
            for thing in self.things:
                for prop in thing['properties']:
                    try:
                        href = ""
                        for i in range(len(thing['properties'][prop]['links'])):
                            if thing['properties'][prop]['links'][i]['rel'] == 'property':
                                href = thing['properties'][prop]['links'][i]['href']
                    
                        if href != "":
                            #print("href = " + str(href))
                            prop_val = self.api_get(href)
                            for key in prop_val:
                                if key != 'error':
                                    
                                    if 'value' in self.things[thing_counter]['properties'][prop]:
                                        #print("old val: " + str( self.things[thing_counter]['properties'][prop]['value'] ))
                                        self.things[thing_counter]['properties'][prop]['value'] = prop_val[key] #['links'][i]['href']
                                        #print("updated val: " + str( self.things[thing_counter]['properties'][prop]['value'] ))
                                    else:
                                        pass
                                        #print("the property didn't have a value?")
                                        #print(str( self.things[thing_counter]['properties'][prop] ))
                                    
                                else:
                                    #print("-- api gave error --")
                                    pass
                        
                    except Exception as ex:
                        if self.DEBUG:
                            print("error in property check loop: " + str(ex))
                    
                    prop_counter += 1
                thing_counter += 1 
                 
            if self.DEBUG:
                print("things counter: " + str(thing_counter))
                print("properties counter: " + str(prop_counter))
                        
                    #print("prop name: " + str(prop['name']))
        except Exception as ex:
            print("error in update_things: " + str(ex))
            



#
#  HANDLE REQUEST
#

    def handle_request(self, request):
        """
        Handle a new API request for this handler.

        request -- APIRequest object
        """
        if self.DEBUG:
            print("> > >  REQUEST < < <")
        try:
        
            if request.method != 'POST':
                print("- was POST request, ignoring")
                return APIResponse(status=404)
            
            if request.path == '/ajax':
                
                action = str(request.body['action'])    
                print("ajax action = " + str(action))
                
                if action == 'init':
                    print('ajax handling init')
                    print("self.persistent_data = " + str(self.persistent_data))
                    return APIResponse(
                      status=200,
                      content_type='application/json',
                      content=json.dumps({'state' : True, 'message' : 'initialisation complete', 'persistent_data': self.persistent_data }),
                    )
                    
                    
                else:
                    return APIResponse(status=404)
                    
            else:
                return APIResponse(status=404)
                
        except Exception as e:
            print("Failed to handle UX extension API request: " + str(e))
            return APIResponse(
              status=500,
              content_type='application/json',
              content=json.dumps("API Error"),
            )





    def unload(self):
        self.running = False
        if self.DEBUG:
            print("Webinterface api handler shutting down")




    #def cancel_pairing(self):
    #    """Cancel the pairing process."""

        # Get all the things via the API.
    #    try:
    #        self.things = self.api_get("/things")
    #        #print("Did the things API call")
    #    except Exception as ex:
    #        print("Error, couldn't load things at init: " + str(ex))




#
#  API
#

    def api_get(self, api_path):
        """Returns data from the WebThings Gateway API."""
        #if self.DEBUG:
        #    print("GET PATH = " + str(api_path))
        #print("GET TOKEN = " + str(self.token))
        if self.token == None:
            print("PLEASE ENTER YOUR AUTHORIZATION CODE IN THE SETTINGS PAGE")
            return []
        
        try:
            r = requests.get(self.server + api_path, headers={
                  'Content-Type': 'application/json',
                  'Accept': 'application/json',
                  'Authorization': 'Bearer ' + str(self.token),
                }, verify=False, timeout=5)
            #if self.DEBUG:
            #    print("API GET: " + str(r.status_code) + ", " + str(r.reason))

            if r.status_code != 200:
                #if self.DEBUG:
                #    print("API GET returned a status code that was not 200. It was: " + str(r.status_code))
                return {"error": r.status_code}
                
            else:
                #if self.DEBUG:
                #    print("API get succesfull: " + str(r.text))
                return json.loads(r.text)
            
        except Exception as ex:
            print("Error doing " + str(api_path) + " request/loading returned json: " + str(ex))
            #return [] # or should this be {} ? Depends on the call perhaps.
            return {"error": 500}


    def api_put(self, api_path, json_dict):
        """Sends data to the WebThings Gateway API."""

        if self.DEBUG:
            print("PUT > api_path = " + str(api_path))
            print("PUT > json dict = " + str(json_dict))
            #print("PUT > self.server = " + str(self.server))
            #print("PUT > self.token = " + str(self.token))
            

        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(self.token),
        }
        try:
            r = requests.put(
                self.server + api_path,
                json=json_dict,
                headers=headers,
                verify=False,
                timeout=3
            )
            #if self.DEBUG:
            #print("API PUT: " + str(r.status_code) + ", " + str(r.reason))

            if r.status_code != 200:
                #if self.DEBUG:
                #    print("Error communicating: " + str(r.status_code))
                return {"error": str(r.status_code)}
            else:
                if self.DEBUG:
                    print("API PUT response: " + str(r.text))
                return json.loads(r.text)

        except Exception as ex:
            print("Error doing http request/loading returned json: " + str(ex))
            #return {"error": "I could not connect to the web things gateway"}
            #return [] # or should this be {} ? Depends on the call perhaps.
            return {"error": 500}




#
#  SAVE TO PERSISTENCE
#

    def save_persistent_data(self):
        #if self.DEBUG:
        print("Saving to persistence data store at path: " + str(self.persistence_file_path))
            
        try:
            if not os.path.isfile(self.persistence_file_path):
                open(self.persistence_file_path, 'a').close()
                if self.DEBUG:
                    print("Created an empty persistence file")
            #else:
            #    if self.DEBUG:
            #        print("Persistence file existed. Will try to save to it.")


            with open(self.persistence_file_path) as f:
                if self.DEBUG:
                    print("saving persistent data: " + str(self.persistent_data))
                json.dump( self.persistent_data, open( self.persistence_file_path, 'w+' ) )
                return True

        except Exception as ex:
            print("Error: could not store data in persistent store: " + str(ex) )
            return False


    
    
    
    
def get_int_or_float(v):
    number_as_float = float(v)
    number_as_int = int(number_as_float)
    if number_as_float == number_as_int:
        return number_as_int
    else:
        return float( int( number_as_float * 1000) / 1000)
        
        
        



#
#  ADAPTER
#        
        
class WebinterfaceAdapter(Adapter):
    """Adapter that can hold and manage things"""

    def __init__(self, api_handler, verbose=False):
        """
        Initialize the object.

        verbose -- whether or not to enable verbose logging
        """

        self.api_handler = api_handler
        self.name = self.api_handler.addon_name #self.__class__.__name__
        #print("adapter name = " + self.name)
        self.adapter_name = self.api_handler.addon_name #'Webinterface-adapter'
        Adapter.__init__(self, self.adapter_name, self.adapter_name, verbose=verbose)
        self.DEBUG = self.api_handler.DEBUG
        
        try:
            # Create the thing
            webinterface_device = WebinterfaceDevice(self,api_handler,"webinterface","Web interface","OnOffSwitch")
            self.handle_device_added(webinterface_device)
            self.devices['webinterface'].connected = True
            self.devices['webinterface'].connected_notify(True)
            self.thing = self.get_device("webinterface")
        
        except Exception as ex:
            print("Error during adapter init: " + str(ex))


    def remove_thing(self, device_id):
        if self.DEBUG:
            print("Removing webinterface thing: " + str(device_id))
        
        try:
            obj = self.get_device(device_id)
            self.handle_device_removed(obj)                     # Remove from device dictionary

        except Exception as ex:
            print("Could not remove thing from Webinterface adapter devices: " + str(ex))
        


#
#  DEVICE
#

class WebinterfaceDevice(Device):
    """Webinterface device type."""

    def __init__(self, adapter, api_handler, device_name, device_title, device_type):
        """
        Initialize the object.
        adapter -- the Adapter managing this device
        """

        
        Device.__init__(self, adapter, device_name)
        #print("Creating Webinterface thing")
        
        self._id = device_name
        self.id = device_name
        self.adapter = adapter
        self.api_handler = api_handler
        self._type.append(device_type)
        #self._type = ['OnOffSwitch']

        self.name = device_name
        self.title = device_title
        self.description = 'Control devices via via the internet'

        #if self.adapter.DEBUG:
        #print("Empty Webinterface thing has been created. device_name = " + str(self.name))
        #print("new thing's adapter = " + str(self.adapter))

        #print("self.api_handler.persistent_data['enabled'] = " + str(self.api_handler.persistent_data['enabled']))
        
        self.properties["outside-access"] = WebinterfaceProperty(
                            self,
                            "outside-access",
                            {
                                '@type': 'OnOffProperty',
                                'title': "Outside access",
                                'type': 'boolean',
                                'readOnly': False,
                            },
                            self.api_handler.persistent_data['enabled'])

        
        self.properties["anonymous-id"] = WebinterfaceProperty(
                            self,
                            "anonymous-id",
                            {
                                'title': "Annymous ID",
                                'type': 'string',
                                'readOnly': True,
                            },
                            self.api_handler.persistent_data['uuid'])

        #targetProperty = self.find_property('outside-access')
        #targetProperty.update(self.api_handler.persistent_data['enabled'])

        #print(str(self.properties["outside-access"]))


#
#  PROPERTY
#


class WebinterfaceProperty(Property):
    """Webinterface property type."""

    def __init__(self, device, name, description, value):
        Property.__init__(self, device, name, description)
        
        #print("new property with value: " + str(value))
        self.device = device
        self.name = name
        self.title = name
        self.description = description # dictionary
        self.value = value
        self.update(value)
        #self.set_cached_value(value)
        #self.device.notify_property_changed(self)
        #print("property initialized")


    def set_value(self, value):
        print("set_value is called on a Webinterface property. New value: " + str(value))

        try:
            if self.name == "outside-access":
                self.device.api_handler.persistent_data['enabled'] = value
                self.device.api_handler.save_persistent_data()
            self.update(value)
            
        except Exception as ex:
            print("property:set value:error: " + str(ex))
        

    def update(self, value):
        print("webinterface property -> update to: " + str(value))
        #print("--prop details: " + str(self.title) + " - " + str(self.original_property_id))
        #print("--pro device: " + str(self.device))
        if value != self.value:
            self.value = value
            self.set_cached_value(value)
            self.device.notify_property_changed(self)
        
        