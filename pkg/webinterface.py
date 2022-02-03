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
#from passlib.hash import pbkdf2_sha512
import hashlib
import threading
from AesEverywhere import aes256
#import secretstorage

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

        self.api_server = 'http://127.0.0.1:8080'
        self.DEV = True
        self.DEBUG = False
            
        self.things = [] # Holds all the things, updated via the API. Used to display a nicer thing name instead of the technical internal ID.
        self.data_types_lookup_table = {}
        self.token = None

        self.web_url = "https://www.candlesmarthome.com/web"
        self.uuid = ""

        self.total_time_delta = 0
        self.previous_enabled_state = False
        self.last_activity_time = 0
        self.last_active_state = False
        self.previous_full_things = {}
        self.persistent_data = {'ready':False, 'allowed_things':[]}
        self.simple_things = [] # just name and title, used in bheckboxes UI
        self.things_to_send = [] # only allowed things
            
        self.get_all_things_counter = 0
            
        self.should_get_all_things_from_api = True # whenever this is set to true, the complete things list is requested from the API. This is a heavy call.
            
        #print(self.user_profile)
            
        # LOAD CONFIG
        try:
            self.add_from_config()
        except Exception as ex:
            print("Error loading config: " + str(ex))

        #print("self.token = " + str(self.token))
        
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
            self.save_persistent_data()
            
            
        if self.DEBUG:
            print("Webinterface self.persistent_data is now: " + str(self.persistent_data))
            
        if self.persistent_data['uuid'] == "":
            self.get_new_uuid()
            
        if 'enabled' not in self.persistent_data:
            self.persistent_data['enabled'] = True
            self.save_persistent_data()
            
        if 'hash' not in self.persistent_data:
            self.persistent_data['hash'] = None
            self.missing_hash = True
            
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
        
        
        # start adapter
        try:
            self.adapter = WebinterfaceAdapter(self,verbose=False)
            #self.manager_proxy.add_api_handler(self.extension)
            print("ADAPTER created")
            pass
        except Exception as ex:
            print("Failed to start ADAPTER. Error: " + str(ex))
            



        # Start the internal clock

        try:      
            #if self.DEBUG:
            #    print("Starting the internal clock")
            if self.token != None:
                
                self.update_things() 
                      
                t = threading.Thread(target=self.clock)
                t.daemon = True
                t.start()
                #pass
        except:
            print("Error starting the clock thread")



    def get_new_uuid(self):
        # clear old data
        if 'hash' in self.persistent_data:
            if self.persistent_data['hash'] != None:
                r = requests.post(self.web_url + 'receiver.php', data={"hash":self.persistent_data['hash'], "time":0 })
                a = requests.post(self.web_url + 'get_actions.php', data={"hash":self.persistent_data['hash'], "uuid":self.persistent_data['uuid'] })
              
        # get new UUID
        a = requests.get(self.web_url + 'uuid.php')
        #print("actions data: " + str(a.content))
        uuid_json = a.json()
        if self.DEBUG:
            print("new anonymous ID: " + str(uuid_json))
        if uuid_json['uuid'] != "error":
            self.persistent_data['uuid'] = uuid_json['uuid']
            self.save_persistent_data()



    # Read the settings from the add-on settings page
    def add_from_config(self):
        """Attempt to read config data."""
        try:
            database = Database(self.addon_name)
            if not database.open():
                print("Could not open settings database")
                self.close_proxy()
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
            self.close_proxy()
            return
        
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
        
        # Web url
        try:
            if 'Web location' in config:
                if len(str(config['Web location'])) > 5:
                    self.web_url = str(config['Web location'])
                    if not self.web_url.endswith("/"):
                        self.web_url += "/"
                    print("-Web location is present in the config data: " + str(self.web_url))
                else:
                    self.web_url = "https://www.candlesmarthome.com/web"
            else:
                self.web_url = "https://www.candlesmarthome.com/web"
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
                
                if self.last_active_state == True and self.last_activity_time < time.time() - 60:
                    self.last_active_state = False
                    self.adapter.devices['webinterface'].properties["activity"].update(False) # the outside user is no longer active
                
                #if not hasattr(self.persistent_data, 'hash'):
                if not 'hash' in self.persistent_data:
                    #if self.DEBUG:
                    #    print("missing hash: " + str(self.persistent_data))
                    continue
                    
                if self.persistent_data['hash'] == None:
                    #if self.DEBUG:
                    #    print("hash was still none: " + str(self.persistent_data))
                    continue
                    
                if self.persistent_data['enabled']:
                    self.previous_enabled_state = True
                    #print("Did the things API call. Self.things is now:")
                    #print(str(self.things))
                    if self.DEBUG:
                        print(str(seconds_counter))
                    #print(str( self.web_url + "gettime.php" ))
                
                    parameters = {"fresh":False, "hash": self.persistent_data['hash'], "uuid": self.persistent_data['uuid'] }
                    if self.DEBUG:
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
                        if self.DEBUG:
                            print(str(timejson['time']))
                        time_delta = abs( time.time() - ( timejson['time'] ) ) # / 1000
                        self.total_time_delta += time_delta
                        if self.DEBUG:
                            print("time delta: " + str( time_delta ) )
                            print("total time delta: " + str( self.total_time_delta ) )
                        #print("")
                        #print("timejson password = " + str(timejson['password']))
                        #print("self.persistent_data['hash'] = " + str(self.persistent_data['hash']))
                        
                        if time_delta < 15:
                            if 'hash' in timejson:
                                if self.persistent_data['hash'] == str(timejson['hash']):
                                    #print("hash == hash, and time is ok too.")
                    
                                    self.last_activity_time = time.time()
                                    
                                    if self.last_active_state == False:
                                        self.last_active_state = True
                                        self.adapter.devices['webinterface'].properties["activity"].update(True) # Indicate that someone is accessing the system from the outside
                                    
                                    # First, check if there are any actions that need to be performed buffered on the server.
                                    try:
                                        a = requests.post(self.web_url + 'get_actions.php', data={"hash":self.persistent_data['hash'], "uuid":self.persistent_data['uuid'] })
                                        if self.DEBUG:
                                            print("actions data: " + str(a.content))
                                            
                                        if len(str(a.content)) > 5:
                                            
                                            messages = a.json()
                                            if self.DEBUG:
                                                print(str("message json: " + str(messages))) 
                                            #print(aes256.decrypt(encrypted, self.persistent_data['hash']))
                                            for message in messages:
                                                if 'encrypted' in message:
                                                    encrypted = message['encrypted']
                                                    if self.DEBUG:
                                                        print("action encrypted = " + str(encrypted))
                                                    #decrypted = aes256.decrypt(encrypted, keyring.get_password('webinterface', webinterface) ) #self.persistent_data['password'])
                                                    decrypted = aes256.decrypt(encrypted, self.persistent_data['password'] )
                                                
                                                    if self.DEBUG:
                                                        print("actions decrypted = " + str(decrypted))
                                                    action = json.loads( decrypted )
                                                    if self.DEBUG:
                                                        print("action dict: " + str(action))
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
                            
                                            #if self.persistent_data['hash'] == str(action['hash']):
                                            #    print("GOOD HASH")
                                
            
                                    time.sleep(.1)
                                    if self.total_time_delta > 5:
                                        self.total_time_delta = 0
                                        if self.DEBUG:
                                            print("Password ok, and some time has passed. Posting to web")

                                        #print("")
                                        #print("__THINGS__")
                                        #print("")
                                        #print(str(self.things))
                                        self.update_things() # this goes over every property and gets the actual latest value. It also creates the list of things data that is allowed to be sent.
                                        #print("")
                                        #print("")
                                        
                                        things_string = json.dumps(self.things_to_send)
                                        if self.DEBUG:
                                            print("sending: " + str(things_string))
                                        #encrypted_string = aes256.encrypt(things_string, keyring.get_password('webinterface', webinterface))
                                        encrypted_string = aes256.encrypt(things_string, self.persistent_data['password'])
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
                                        
                                        r = requests.post(self.web_url + 'receiver.php', data={"hash":self.persistent_data['hash'], "uuid":self.persistent_data['uuid'], "time":time.time(), "encrypted":encrypted_string.decode('utf-8') }) # json={"hash":self.persistent_data['hash'],"encrypted": encrypted_string.decode('utf-8')})
                                        
                                else:
                                    if self.DEBUG:
                                        print("hashes (passwords) did not match")
                                    if seconds_counter == 0:
                                        r = requests.post(self.web_url + 'receiver.php', data={"hash":self.persistent_data['hash'], "time":0 })
                    
                        # if time_delta > 15 seconds
                        else:
                            r = requests.post(self.web_url + 'receiver.php', data={"hash":self.persistent_data['hash'], "time":0 }) # ask the server to delete all the data (which it does by itself already too)
                 
                else:
                    if self.previous_enabled_state == True:
                        # Delete all data on the webserver.
                        r = requests.post(self.web_url + 'receiver.php', data={"hash":self.persistent_data['hash'], "time":0 })
                        a = requests.post(self.web_url + 'get_actions.php', data={"hash":self.persistent_data['hash'], "uuid":self.persistent_data['uuid'] })
                        self.previous_enabled_state = False
                
            except Exception as ex:
                print("Clock: error preparing updated things data: " + str(ex))
                        


    # The api request to /things doesn't serve the latest data somehow. This fixes that.
    def update_things(self):
        if self.DEBUG:
            print("in update things")
        try:
            
           # do_api_call_for_all_things = True
            if self.should_get_all_things_from_api:
                if self.DEBUG:
                    print("update all the things")
                api_response = self.api_get("/things")
            
                if 'error' in api_response:
                    if self.DEBUG:
                        print("update_things: the API call for all things resulted in an error. Stopping.")
                    return
                
                else:
                    self.things = api_response
                    self.should_get_all_things_from_api = False
            
            else:
                self.get_all_things_counter += 1
                if self.get_all_things_counter == 200: # once every 200 loops we query the API for the complete things data
                    self.should_get_all_things_from_api = True
                    self.get_all_things_counter = 0
                
            #print(str(self.things))
                
            thing_counter = -1
            prop_counter = 0
            new_simple_things = []

            for thing in self.things:
                thing_counter += 1 
                try:
                    thing_name = thing['href'].rsplit('/', 1)[-1]
                    #print("thing: " + str(thing))
                    new_simple_things.append({'title':thing['title'], 'name':thing_name})
                except Exception as ex:
                    print("update things: no thing name?" + str(ex))
                
                if 'allowed_things' in self.persistent_data:
                    if thing_name not in self.persistent_data['allowed_things']:
                        continue
                else:
                    continue
                
                for prop in thing['properties']:
                    try:
                        href = ""
                        
                        if len(thing['properties'][prop]['links']) != 0:
                            for i in range(len(thing['properties'][prop]['links'])):
                                if thing['properties'][prop]['links'][i]['rel'] == 'property':
                                    href = thing['properties'][prop]['links'][i]['href']
                                    
                        elif 'forms' in thing['properties'][prop]:
                            for i in range(len(thing['properties'][prop]['forms'])):
                                if thing['properties'][prop]['forms'][i]['rel'] == 'property':
                                    href = thing['properties'][prop]['forms'][i]['href']
                    
                        if href != "":
                            
                            if self.DEBUG:
                                print("href = " + str(href))
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
                
                 
            if self.DEBUG:
                print("things counter: " + str(thing_counter))
                print("properties counter: " + str(prop_counter))
                       
            
            self.simple_things = new_simple_things
            
            # create subset of things that may be sent
            
            to_send = []
            for thing in self.things:
                try:
                    thing_name = thing['href'].rsplit('/', 1)[-1]
                    if 'allowed_things' in self.persistent_data:
                        if thing_name in self.persistent_data['allowed_things']:
                            # TODO maybe implement a system that checks if things have changed since last time, and only send those.
                            print("allowed thing: " + str(thing_name))
                            to_send.append(thing)
                
                except Exception as ex:
                    print("error in creating allowed things data: " + str(ex))
            self.things_to_send = to_send
            
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
                if self.DEBUG:
                    print("- was not POST request, ignoring")
                return APIResponse(status=404)
            
            if request.path == '/ajax':
                
                action = str(request.body['action'])    
                print("ajax action = " + str(action))
                
                #persist = self.persistent_data.copy()
                #del persist['password']
                
                if action == 'init':
                    if self.DEBUG:
                        print('ajax handling init')
                        print("self.persistent_data = " + str(self.persistent_data))
                    return APIResponse(
                      status=200,
                      content_type='application/json',
                      content=json.dumps({'state' : True, 'message' : '', 'web_url': self.web_url, 'persistent_data': self.persistent_data, 'things':self.simple_things }),
                    )
                    
                elif action == 'get_new_uuid':
                    if self.DEBUG:
                        print('ajax handling get_new_uuid')
                    self.get_new_uuid()
                    time.sleep(.4)
                    return APIResponse(
                      status=200,
                      content_type='application/json',
                      content=json.dumps({'state' : True, 'message' : '', 'web_url': self.web_url, 'persistent_data': persist }),
                    )
                    
                elif action == 'save_hash':
                    if self.DEBUG:
                        print('ajax handling save_hash')
                        
                    #self.persistent_data['password'] = str(request.body['password'])
                    try:
                        #connection = secretstorage.dbus_init()
                        #collection = secretstorage.get_default_collection(connection)
                        #attributes = {'application': 'webinterface', 'password': str(request.body['password'])}
                        #item = collection.create_item('webinterface', attributes, b'pa$$word')
                            
                        #keyring.set_password("webinterface", "webinterface", str(request.body['password']))
                        self.persistent_data['password'] = str(request.body['password'])
                        
                    except Exception as ex:
                        print("Error saving password in secure storage: " + str(ex))
                    
                    #self.persistent_data['hash'] = str(request.body['hash']) # if the browser UI generates the hash, it might improve cmopatibiity, since the same libraries will be used.
                    self.persistent_data['hash'] = str( hashlib.sha512( bytes(self.persistent_data['password'], 'utf-8') ).hexdigest() )
                    self.save_persistent_data()
                    
                    return APIResponse(
                      status=200,
                      content_type='application/json',
                      content=json.dumps({'state' : True, 'message' : '', 'web_url': self.web_url, 'persistent_data': self.persistent_data }),
                    )
                    
                # Save which devices may be accessed
                elif action == 'save_allowed':
                    state = True
                    if self.DEBUG:
                        print('ajax handling save_allowed')
                    if 'allowed_things' in request.body:
                        self.persistent_data['allowed_things'] = request.body['allowed_things']
                        self.save_persistent_data()
                    else:
                        state = False
                        
                    return APIResponse(
                      status=200,
                      content_type='application/json',
                      content=json.dumps({'state' : state, 'message' : '' }),
                    )
                    
                # Whether outside access is allowed at all
                elif action == 'outside_access':
                    state = True
                    if self.DEBUG:
                        print('ajax handling save_allowed')
                    try:
                        if 'state' in request.body:
                            self.adapter.devices['webinterface'].properties["outside-access"].update(request.body['state'])
                            self.persistent_data['enabled'] = True
                            self.save_persistent_data()
                        else:
                            state = False
                    except Exception as ex:
                        print("Error setting outside access state: " + str(ex))
                        state = False
                        
                    return APIResponse(
                      status=200,
                      content_type='application/json',
                      content=json.dumps({'state' : state, 'message' : '' }),
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

    def api_get(self, api_path,intent='default'):
        """Returns data from the WebThings Gateway API."""
        if self.DEBUG:
            print("GET PATH = " + str(api_path))
            #print("intent in api_get: " + str(intent))
        #print("GET TOKEN = " + str(self.token))
        if self.token == None:
            print("API GET: PLEASE ENTER YOUR AUTHORIZATION CODE IN THE SETTINGS PAGE")
            #self.set_status_on_thing("Authorization code missing, check settings")
            return []
        
        try:
            r = requests.get(self.api_server + api_path, headers={
                  'Content-Type': 'application/json',
                  'Accept': 'application/json',
                  'Authorization': 'Bearer ' + str(self.token),
                }, verify=False, timeout=5)
            if self.DEBUG:
                print("API GET: " + str(r.status_code) + ", " + str(r.reason))

            if r.status_code != 200:
                if self.DEBUG:
                    print("API returned a status code that was not 200. It was: " + str(r.status_code))
                return {"error": str(r.status_code)}
                
            else:
                to_return = r.text
                try:
                    if self.DEBUG:
                        print("api_get: received: " + str(r))
                    #for prop_name in r:
                    #    print(" -> " + str(prop_name))
                    if not '{' in r.text:
                        if self.DEBUG:
                            print("api_get: response was not json (gateway 1.1.0 does that). Turning into json...")
                        
                        if 'things/' in api_path and '/properties/' in api_path:
                            if self.DEBUG:
                                print("properties was in api path: " + str(api_path))
                            likely_property_name = api_path.rsplit('/', 1)[-1]
                            to_return = {}
                            to_return[ likely_property_name ] = json.loads(r.text)
                            if self.DEBUG:
                                print("returning fixed: " + str(to_return))
                            return to_return
                                
                except Exception as ex:
                    print("api_get_fix error: " + str(ex))
                        
                if self.DEBUG:
                    print("returning without 1.1.0 fix")
                return json.loads(r.text)
            
        except Exception as ex:
            print("Error doing http request/loading returned json: " + str(ex))
            
            #return [] # or should this be {} ? Depends on the call perhaps.
            return {"error": 500}



    def api_put(self, api_path, json_dict, intent='default'):
        """Sends data to the WebThings Gateway API."""
        
        try:
        
            if self.DEBUG:
                print("PUT > api_path = " + str(api_path))
                print("PUT > json dict = " + str(json_dict))
                print("PUT > self.api_server = " + str(self.api_server))
                print("PUT > intent = " + str(intent))
                print("self.gateway_version: " + str(self.gateway_version))
        
            simplified = False
            property_was = None
            if self.gateway_version != "1.0.0":
        
                if 'things/' in api_path and '/properties/' in api_path:
                    if self.DEBUG:
                        print("PUT: properties was in api path: " + str(api_path))
                    for bla in json_dict:
                        property_was = bla
                        simpler_value = json_dict[bla]
                        json_dict = simpler_value
                    #simpler_value = [elem[0] for elem in json_dict.values()]
                    if self.DEBUG:
                        print("simpler 1.1.0 value to put: " + str(simpler_value))
                    simplified = True
                    #likely_property_name = api_path.rsplit('/', 1)[-1]
                    #to_return = {}
            
            
        except Exception as ex:
            print("Error preparing PUT: " + str(ex))

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(self.token),
        }
        try:
            r = requests.put(
                self.api_server + api_path,
                json=json_dict,
                headers=headers,
                verify=False,
                timeout=5
            )
            if self.DEBUG:
                print("API PUT: " + str(r.status_code) + ", " + str(r.reason))
                print("PUT returned: " + str(r.text))

            if r.status_code != 200:
                if self.DEBUG:
                    print("Error communicating: " + str(r.status_code))
                return {"error": str(r.status_code)}
            else:
                if simplified:
                    return_value = {property_was:json.loads(r.text)} # json.loads('{"' + property_was + '":' + r.text + '}')
                else:
                    return_value = json.loads(r.text)
                
                return_value['succes'] = True
                return return_value

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
        if self.DEBUG:
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
            webinterface_device = WebinterfaceDevice(self,api_handler,"webinterface","Web interface")
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
        

    def cancel_pairing(self):
        if self.DEBUG:
            print("cancel_pairing detected")
        self.api_handler.should_get_all_things_from_api = True


#
#  DEVICE
#

class WebinterfaceDevice(Device):
    """Webinterface device type."""

    def __init__(self, adapter, api_handler, device_name, device_title):
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
        self._type.append("OnOffSwitch")
        self._type.append("BinarySensor")
        #self._type = ['OnOffSwitch']

        self.name = device_name
        self.title = device_title
        self.description = 'Control devices from the internet'

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

        
        self.properties["activity"] = WebinterfaceProperty(
                            self,
                            "activity",
                            {
                                '@type': 'BooleanProperty',
                                'title': "Activity",
                                'type': 'boolean',
                                'readOnly': True,
                            },
                            False)
        
        """
        self.properties["anonymous-id"] = WebinterfaceProperty(
                            self,
                            "anonymous-id",
                            {
                                'title': "Annymous ID",
                                'type': 'string',
                                'readOnly': True
                            },
                            self.api_handler.persistent_data['uuid'])

        """
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
        #print("set_value is called on a Webinterface property. New value: " + str(value))

        try:
            if self.name == "outside-access":
                self.device.api_handler.persistent_data['enabled'] = value
                self.device.api_handler.save_persistent_data()
            self.update(value)
            
        except Exception as ex:
            print("property:set value:error: " + str(ex))
        

    def update(self, value):
        #print("webinterface property -> update to: " + str(value))
        #print("--prop details: " + str(self.title) + " - " + str(self.original_property_id))
        #print("--pro device: " + str(self.device))
        if value != self.value:
            self.value = value
            self.set_cached_value(value)
            self.device.notify_property_changed(self)
        
        