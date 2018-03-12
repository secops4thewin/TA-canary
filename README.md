# Thinkst Canary AddOn For Splunk

## Canary About
Most companies find out way too late that they have been breached. Even with millions of dollars invested in security, over-worked admins and ignored alerts do little to help.

But what if there were a simpler, more reliable signal than malware signatures? Wouldn't you want to know if someone was opening 'passwords.xls' on \\NetworkTeam_FS1, or brute-forcing an SSH server on your DataBase segment?

Thinkst Canary can be deployed in under 3 minutes (even on complex networks) and is a clear, high quality marker of compromise. Know. When it Matters.

## Overview
This Add-On allows the analyst to collect data from the Canary Tools API.  In addition, Adaptive response actions have been provisioned to allow you to automate responses to alerts

## Thinkst Canary AddOn For Splunk
This Add-On requires access to the Canary Tools API and for the API to be enabled within your Canary Console and the Splunk Common Information Model App located [here](https://splunkbase.splunk.com/app/1621/).  In addition a heavy forwarder will need to be setup as this will act as the server that collects data for indexing.

### Canary Tools Setup
1. Visit your canary console by going to https://yourconsole.canary.tools/settings
2. Scroll down to API and click on.
3. Enter your password at the top of the page twice 
4. Click Save
5. Take note of the generated API key.  You will need this.

### Splunk Installation
1. Git clone this directory 'git clone https://github.com/secops4thewin/TA-canary'
2. Install the add-on to the indexer, heavy forwarder and search head in your Splunk environment
3. On the Search Head open a browser to to http://yoursplunkserver:8000/en-GB/app/TA-canary/configuration
4. Enable a proxy if it is required
5. Click Add-on Settings and enter the API Key from Step 5 above.
6. Enter your Canary Domain, if your full domain is https://yourconsole.canary.tools/ then use 'yourconsole'. 
7. Click Save
8. Repeat steps 4-7 on the heavy forwarder.
7. If you have proxy rules  allow https://*.canary.tools/ from your Search Head and Heavy Forwarder


## Release Notes
1.0.0 Initial release with API functionality