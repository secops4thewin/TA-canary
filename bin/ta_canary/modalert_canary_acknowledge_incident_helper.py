
# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the setup parameters and prints them to the log
    canary_domain = helper.get_global_setting("canary_domain")
    helper.log_info("canary_domain={}".format(canary_domain))
    api_key = helper.get_global_setting("api_key")
    helper.log_info("api_key={}".format(api_key))

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
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


    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the alert action parameters and prints them to the log
    incident_id = helper.get_param("incident_id")
    helper.log_info("incident_id={}".format(incident_id))

    index_name = helper.get_param("index_name")
    helper.log_info("index_name={}".format(index_name))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """
    import json
    import time
    helper.log_info("Alert action canary_acknowledge_incident started.")
    
    domain = helper.get_global_setting('canary_domain')
    api_key = helper.get_global_setting("api_key")
    
    #Check to see if proxy setting is configured
    proxy = helper.get_proxy()
    
    if proxy:
        use_proxy = True
    else:
        use_proxy = False
    
    #Set a custom useragent header for Splunk API so Canary.tools can see the use of the product
    headers = {'User-Agent': 'Splunk API Call'}
    
    #Get ID of Incident
    incident_id = helper.get_param("incident_id")
    
    #Get Index Name
    index_name = helper.get_param("index_name")
    
    #Get current time for testing purposes.    
    current_time = time.time()
    
    #Post Data
    #post_data = "incident={}".format(incident_id)
    post_data = "incident={}".format(incident_id)
    
    #Pass the domain and the api key to the url.
    url = "https://{}.canary.tools/api/v1/incident/acknowledge?auth_token={}".format(domain,api_key)
    
    #Set the method of Get to the console
    method = "POST"
    
    #Try the first connection to see if it works.
    response = helper.send_http_request(url, method, parameters=post_data,payload=None, headers=headers, cookies=None, verify=True, cert=None, timeout=None, use_proxy=use_proxy)
    
    
    try:
        response    
        
    except Exception as e:
        helper.log_error("Error occured with canary.tools Acknowledging an incident. Error Message: {}, Attempted URL: {}".format(e,url))
        sys.exit()
    
    if response.status_code == 200:
        #Successfull Connection
        helper.log_info("Successfully acknowledged incident")
        
        data = response.json()
        data['api_call'] = 'Incident Acknowledged'
        data['_time'] = current_time
        json_data = json.dumps(data)
        
        helper.addevent(json_data, sourcetype="canarytools:ar")
        
        helper.writeevents(source="canary_toolsapi", index=index_name, host="adaptive_response")
        
    else:
        data = response.json()
        data['api_call'] = 'Incident Acknowledged'
        data['_time'] = current_time
        data['url'] = url
        json_data = json.dumps(data)
        helper.addevent(json_data, sourcetype="canarytools:ar")
        helper.writeevents(source="canary_toolsapi", index=index_name, host="adaptive_response")
        helper.log_error("Error occured with canary.tools Acknowledging an incident. Attempted URL: {}".format(url))
        
    # TODO: Implement your alert action logic here
    return 0
