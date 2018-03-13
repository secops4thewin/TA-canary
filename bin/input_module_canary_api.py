
# encoding = utf-8

import sys
import time
import json
'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    pass

def collect_events(helper, ew):
    domain = helper.get_global_setting('canary_domain')
    api_key = helper.get_global_setting("api_key")
    incident_limit = 20

    #Check to see if proxy setting is configured
    proxy = helper.get_proxy()

    if proxy:
        use_proxy = True
    else:
        use_proxy = False

    #Set a custom useragent header for Splunk API so Canary.tools can see the use of the product
    headers = {'User-Agent': 'Splunk API Call'}

    #Pass the domain and the api key to the url.
    url = "https://{}.canary.tools/api/v1/ping?auth_token={}".format(domain,api_key)

    #Set the method of Get to the console
    method = "GET"
    #Try the first connection to see if it works.
    response = helper.send_http_request(url, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

    try:
        response
    except Exception as e:
        helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(e))
        sys.exit()

    if response.status_code == 200:
        #Successfull Connection
        helper.log_info("Successfully connected to Canary.tools API")

        #Get current time for testing purposes.
        current_time = time.time()

        #Collect All incidents from Canary Tools
        url_allIncidents    = "https://{}.canary.tools/api/v1/incidents/all?auth_token={}&tz=UTC&limit={}".format(domain,api_key,incident_limit)
        helper.log_info("Checking last_seen_time")
        if helper.get_check_point('last_seen_time'):
            url_allIncidents += '&newer_than={}'.format(time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime(helper.get_check_point('last_seen_time'))))
            helper.log_info("last_seen_time URL is {}".format(url_allIncidents))
        url_cursorIncidents = "https://{}.canary.tools/api/v1/incidents/all?auth_token={}&tz=UTC&cursor=".format(domain,api_key)

        #Collect All Registered Devices from Canary Tools
        url_regDevices = "https://{}.canary.tools/api/v1/devices/all?auth_token={}&tz=UTC".format(domain,api_key)

        #Collect All Canary Tokens from Canary Tools
        url_canarytokens_fetch = "https://{}.canary.tools/api/v1/canarytokens/fetch?auth_token={}".format(domain,api_key)

        #Issue a new response to the Registered DevicesAPI
        response_regDevices = helper.send_http_request(url_regDevices, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Issue a new response to the Canary Tokens API
        response_canarytokens_fetch = helper.send_http_request(url_canarytokens_fetch, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Try to connect to the url for registered devices
        try:
            response_regDevices
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all registered devices. Error Message: {}".format(e))

        #Try to connect to the url for canary tokens
        try:
            response_canarytokens_fetch
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all canary tokens. Error Message: {}".format(e))

        #Issue a new response to the All Incidents API
        response_allIncidents = helper.send_http_request(url_allIncidents, method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)

        #Try to connect to the url for All Incidents
        try:
            response_allIncidents
        #Throw an exception if it fails
        except Exception as e:
            helper.log_error("Error occured with canary.tools API call to retrieve all Incidents. Error Message: {}".format(e))

        most_recent_timestamp = 0
        while response_allIncidents.status_code == 200:
            #If we receive a 200 response from the all incidents API
            #Output the results to json
            data = response_allIncidents.json()

            if len(data['incidents']) >0:
                for a in data['incidents']:
                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:incidents")
                    ew.write_event(event)
                    try:
                        created_timestamp = long(a['description']['created'])
                        if created_timestamp > most_recent_timestamp:
                            most_recent_timestamp = created_timestamp
                    except (KeyError, ValueError) as e:
                        helper.log_info("Error updating timestamp {}".format(e))

            else:
                #If no incidents have been logged
                #Add current time of server to timestamp
                data['_time'] = current_time
                #Convert data to a string
                data_dump = json.dumps(data)
                #Write the event to the destination index
                event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:incidents")
                ew.write_event(event)

            if not data['cursor']['next']:
                break

            response_allIncidents = helper.send_http_request(url_cursorIncidents+data['cursor']['next'], method,headers=headers, verify=True, timeout=60, use_proxy=use_proxy)
        #If the resposne code from querying the Incidents is not 200
        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_allIncidents.json()))

        if most_recent_timestamp:
            helper.save_check_point('last_seen_time', most_recent_timestamp)

        #If we receive a 200 response from the registered devices API
        if response_regDevices.status_code == 200:
            #Output the results to json
            data = response_regDevices.json()
            if len(data['devices']) >0:
                for a in data['devices']:
                    #Only create a device event for new or changed devices
                    check_point_key = 'device:'+a['id']
                    saved_data = helper.get_check_point(check_point_key)
                    if not saved_data:
                        saved_data = {}

                    monitor_fields = ['name', 'description', 'ip_address', 'live', 'version']
                    fields_changed = False
                    for field in monitor_fields:
                        if a.get(field, None) != saved_data.get(field, None):
                            fields_changed = True
                            break
                    if not fields_changed:
                        continue
                    helper.save_check_point(check_point_key, a)


                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:devices")
                    ew.write_event(event)
            else:
                #If no devices have been registered
                #Add current time of server to timestamp
                data['_time'] = current_time
                #Convert data to a string
                data_dump = json.dumps(data)
                #Write the event to the destination index
                event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:devices")
                ew.write_event(event)
        
        #If the resposne code from querying the Registered devices is not 200
        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_regDevices.json()))
        
        #If we receive a 200 response from the canary tokens API    
        if response_canarytokens_fetch.status_code == 200:
            #Output the results to json
            data = response_canarytokens_fetch.json()
            
            if len(data['tokens']) >0:
                for a in data['tokens']:
                    #Add current time of server to timestamp
                    a['_time'] = current_time
                    #Convert data to a string
                    data_dump = json.dumps(a)
                    #Write the event to the destination index
                    event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:tokens")
                    ew.write_event(event)
            else:
                #If no tokens have been registered
                #Add current time of server to timestamp
                data['_time'] = current_time
                #Convert data to a string
                data_dump = json.dumps(data)
                #Write the event to the destination index
                event = helper.new_event(data_dump, source=helper.get_input_type(), index=helper.get_output_index(),sourcetype="canarytools:tokens")
                ew.write_event(event)
                
           
        
        else:
            helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response_canarytokens_fetch.json()))
        
        
    else:
        helper.log_error("Error occured with canary.tools API call. Error Message: {}".format(response.json()))
    
    """Implement your data collection logic here

    # The following examples get the arguments of this input.
    # Note, for single instance mod input, args will be returned as a dict.
    # For multi instance mod input, args will be returned as a single value.
    opt_domain = helper.get_arg('domain')
    # In single instance mode, to get arguments of a particular input, use
    opt_domain = helper.get_arg('domain', stanza_name)

    # get input type
    helper.get_input_type()

    # The following examples get input stanzas.
    # get all detailed input stanzas
    helper.get_input_stanza()
    # get specific input stanza with stanza name
    helper.get_input_stanza(stanza_name)
    # get all stanza names
    helper.get_input_stanza_names()

    # The following examples get options from setup page configuration.
    # get the loglevel from the setup page
    loglevel = helper.get_log_level()
    # get proxy setting configuration
    proxy_settings = helper.get_proxy()
    # get account credentials as dictionary
    account = helper.get_user_credential_by_username("username")
    account = helper.get_user_credential_by_id("account id")
    # get global variable configuration
    global_api_key = helper.get_global_setting("api_key")

    # The following examples show usage of logging related helper functions.
    # write to the log for this modular input using configured global log level or INFO as default
    helper.log("log message")
    # write to the log using specified log level
    helper.log_debug("log message")
    helper.log_info("log message")
    helper.log_warning("log message")
    helper.log_error("log message")
    helper.log_critical("log message")
    # set the log level for this modular input
    # (log_level can be "debug", "info", "warning", "error" or "critical", case insensitive)
    helper.set_log_level(log_level)

    # The following examples send rest requests to some endpoint.
    response = helper.send_http_request(url, method, parameters=None, payload=None,
                                        headers=None, cookies=None, verify=True, cert=None,
                                        timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()

    # The following examples show usage of check pointing related helper functions.
    # save checkpoint
    helper.save_check_point(key, state)
    # delete checkpoint
    helper.delete_check_point(key)
    # get checkpoint
    state = helper.get_check_point(key)

    # To create a splunk event
    helper.new_event(data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
    """

    '''
    # The following example writes a random number as an event. (Multi Instance Mode)
    # Use this code template by default.
    import random
    data = str(random.randint(0,100))
    event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=data)
    ew.write_event(event)
    '''

    '''
    # The following example writes a random number as an event for each input config. (Single Instance Mode)
    # For advanced users, if you want to create single instance mod input, please use this code template.
    # Also, you need to uncomment use_single_instance_mode() above.
    import random
    input_type = helper.get_input_type()
    for stanza_name in helper.get_input_stanza_names():
        data = str(random.randint(0,100))
        event = helper.new_event(source=input_type, index=helper.get_output_index(stanza_name), sourcetype=helper.get_sourcetype(stanza_name), data=data)
        ew.write_event(event)
    '''
