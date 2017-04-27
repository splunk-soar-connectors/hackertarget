# --
# File: hackertarget_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from hackertarget_consts import *

import requests, time
import simplejson as json

requests.packages.urllib3.disable_warnings()


class HackerTargetConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_TRACEROUTE_IP= "traceroute_ip"
    ACTION_ID_TRACEROUTE_DOMAIN= "traceroute_domain"
    ACTION_ID_PING_IP = "ping_ip"
    ACTION_ID_PING_DOMAIN = "ping_domain"
    ACTION_ID_REVERSE_IP = "reverse_ip"
    ACTION_ID_REVERSE_DOMAIN = "reverse_domain"
    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_GEOLOCATE_IP = "geolocate_ip"
    ACTION_ID_GEOLOCATE_DOMAIN = "geolocate_domain"
    ACTION_ID_GET_HEADERS = "get_headers"
    ACTION_ID_GET_LINKS = "get_links"

    def __init__(self):
        """ """

        self.__id_to_name = {}

        # Call the BaseConnectors init first
        super(HackerTargetConnector, self).__init__()

    def initialize(self):
        """ Called once for every action, all member initializations occur here"""

        config = self.get_config()

        # Get the Base URL from the asset config and so some cleanup
        self._base_url = config.get('base_url', HACKERTARGET_BASE_URL)
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        # The host member extacts the host from the URL, is used in creating status messages
        self._host = self._base_url[self._base_url.find('//') + 2:]

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {'Accept': 'application/json'}

        # The common part after the base url, but before the specific endpoint
        # Intiliazed here and used on every REST endpoint calls
        # self._api_uri = config.get('base_url', HACKERTARGET_BASE_API)
        self._api_uri = HACKERTARGET_BASE_API
        if (self._api_uri.endswith('/')):
            self._api_uri = self._api_uri[:-1]
        # self.save_progress('URI: {} - URL: {}'.format(self._api_uri, self._base_url))
        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, headers={}, params=None, data=None, method="get"):
        """ Function that makes the REST call to the device, generic function that can be called from various action handlers"""

        # Get the config
        config = self.get_config()

        # Create the headers
        headers.update(self._headers)

        if (method in ['put', 'post']):
            headers.update({'Content-Type': 'application/json'})

        # get or post or put, whatever the caller asked us to use, if not specified the default will be 'get'
        request_func = getattr(requests, method)

        # handle the error in case the caller specified a non-existant method
        if (not request_func):
            action_result.set_status(phantom.APP_ERROR, ERR_API_UNSUPPORTED_METHOD, method=method)

        # self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)
        # self.save_progress('Using {0} for authentication'.format(self._auth_method))
        # Make the call
        retry_count = MAX_TIMEOUT_DEF
        success = False
        while not success and (retry_count > 0):
            #
            try:
                r = request_func(self._base_url + self._api_uri + endpoint,  # The complete url is made up of the base_url, the api url and the endpiont
                        # auth=(self._username, self._key),  # The authentication method, currently set to simple base authentication
                        data=json.dumps(data) if data else None,  # the data, converted to json string format if present, else just set to None
                        headers=headers,  # The headers to send in the HTTP call
                        verify=config[phantom.APP_JSON_VERIFY],  # should cert verification be carried out?
                        params=params)  # uri parameters if any
            except Exception as e:
                return (action_result.set_status(phantom.APP_ERROR, ERR_SERVER_CONNECTION, e), r.text)

            # r.encoding='utf-8'

            #self.debug_print('REST url: {0} - attempt: {1}'.format(r.url, (MAX_TIMEOUT_DEF - retry_count)))
            # self.debug_print('REST text: {0}'.format(r.text))
            if r.status_code == 200:
                success = True
            else:
                time.sleep(SLEEP_SECS)
                retry_count -= 1

        # Handle any special HTTP error codes here, many devices return an HTTP error code like 204. The requests module treats these as error,
        # so handle them here before anything else, uncomment the following lines in such cases
        # if (r.status_code >= 500): # these guys like 502/504 errors due to gateway failures, we can retry a few times.
        #    return (phantom.APP_SUCCESS, resp_json)
        # Process errors
        #self.debug_print('Response returned: {}'.format(r.text))
        if (phantom.is_fail(r.status_code) or r.text is False or HACKERTARGET_FAIL_ERROR in r.text):
            self.debug_print('FAILURE: Found in the app response.\nResponse: {}'.format(r.text))
            #if response:
            #    action_result.set_summary({'error' : r.text})
            #self.debug_print(action_result.get_message())
            #action_result.set_summary({'error' : r.text})
            #self.set_status(phantom.APP_ERROR)
            return (phantom.APP_ERROR, r.text)

        if r.text:
            if HACKERTARGET_INPUT_INVALID.lower() in r.text.lower() or HACKERTARGET_NO_RESULTS.lower() in r.text.lower():
                self.debug_print('FAILURE: Found in the app response.\nResponse: {}'.format(r.text))
                #action_result.set_summary({'error' : r.text})
                return (phantom.APP_SUCCESS, ('error: ' + r.text))
        #
        # Handle/process any errors that we get back from the device
        if (r.status_code == 200):
            # Success
            return (phantom.APP_SUCCESS, r.text)

        # Failure
        # action_result.add_data({'raw':r.text})

        # details = json.dumps(resp_json).replace('{', '').replace('}', '')

        # return (action_result.set_status(phantom.APP_ERROR, ERR_FROM_SERVER.format(status=r.status_code, detail=details)), resp_json)
        return (action_result.set_status(phantom.APP_ERROR, ERR_FROM_SERVER.format(status=r.status_code, detail=r.text)), r.text)

    def _geolocate_domain(self, param):
        """ Action handler for the '_ping_host' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_GEOIP_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        if param.get('ip'):
            request_params = {'q' : param.get('ip') }
        else:
            request_params = {'q' : param.get('domain') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        IP Address: 216.58.217.110
        Country: US
        State: California
        City: Mountain View
        Latitude: 37.419201
        Longitude: -122.057404
        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response = response.split('\n')
                for line in (response):
                    linedata = (line.strip().split(':'))
                    if "state" in linedata[0].lower():  # make same as maxmind
                        response_data['state_name'] = linedata[1].strip()
                    elif "city" in linedata[0].lower():
                        response_data['city_name'] = linedata[1].strip()
                    elif "country" in linedata[0].lower():
                        response_data['country_name'] = linedata[1].strip()
                    elif "ip" in linedata[0].lower():
                        response_data['ip'] = linedata[1].strip()
                    else:
                        response_data[linedata[0].strip().lower().replace(' ', '_')] = linedata[1].strip()
    
                # Set the summary and response data
                action_result.add_data(response_data)
                # action_result.set_summary({ 'total_hops': len(response_data)})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def _reverse_domain(self, param):
        """ Action handler for the '_reverse_domain' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # parameters here
        # host - hostname; required.
        if param.get('domain'):
            request_params = {'q' : param.get('domain') }
            endpoint = HACKERTARGET_REVERSEDNS_URI
        else:
            request_params = {'q' : param.get('ip')}
            # endpoint = HACKERTARGET_REVERSEIP_URI - as of writing, reverse ip is busted, but can use reverse dns URI.
            endpoint = HACKERTARGET_REVERSEDNS_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        8.8.8.8 google-public-dns-a.google.com
        """
        """
        Oh, domaintools datapaths:
        action_result.data.*.ip_addresses.*.ip_address    string    ip
        action_result.data.*.ip_addresses.*.domain_count    numeric    
        action_result.data.*.ip_addresses.*.domain_names    string    domain
        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response_data['ip_addresses'] = []
                response = response.strip().split('\n')
                tempresponse_data = {}
                for line in (response):
                    #self.debug_print('Response line: {}'.format(line.split(' ')))
                    ipaddr = line.split(' ')[0]
                    if ipaddr in tempresponse_data.keys():
                        tempresponse_data[ipaddr]['domain_names'].append(line.split(' ')[1])
                        tempresponse_data[ipaddr]['domain_count'] += 1
                    else:
                        tempresponse_data[ipaddr] = { 'ip_address' : ipaddr, 'domain_names' : [line.split(' ')[1]], 'domain_count' : 1 }
                domain_count_total = 0
                for ipaddr in tempresponse_data.keys():
                    response_data['ip_addresses'].append(tempresponse_data[ipaddr])
                    domain_count_total += len(tempresponse_data[ipaddr]['domain_names'])
                # Set the summary and response data
                action_result.add_data(response_data)
                action_result.set_summary({ 'total_domains': domain_count_total, 'total_ips': len(tempresponse_data.keys())})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def _ping_host(self, param):
        """ Action handler for the '_ping_host' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_PING_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        if param.get('domain'):
            request_params = {'q' : param.get('domain') }
        else:
            request_params = {'q' : param.get('ip') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        Starting Nping 0.6.47 ( http://nmap.org/nping ) at 2016-11-03 19:16 UTC
        SENT (0.0255s) Starting TCP Handshake > google.com:80 (216.58.195.78:80)
        RECV (0.0291s) Handshake with google.com:80 (216.58.195.78:80) completed
        SENT (1.0286s) Starting TCP Handshake > google.com:80 (216.58.195.78:80)
        RECV (1.0321s) Handshake with google.com:80 (216.58.195.78:80) completed
        SENT (2.0316s) Starting TCP Handshake > google.com:80 (216.58.195.78:80)
        RECV (2.0351s) Handshake with google.com:80 (216.58.195.78:80) completed
        SENT (3.0346s) Starting TCP Handshake > google.com:80 (216.58.195.78:80)
        RECV (3.0379s) Handshake with google.com:80 (216.58.195.78:80) completed
        SENT (4.0374s) Starting TCP Handshake > google.com:80 (216.58.195.78:80)
        RECV (4.0405s) Handshake with google.com:80 (216.58.195.78:80) completed
         
        Max rtt: 3.635ms | Min rtt: 3.207ms | Avg rtt: 3.451ms
        TCP connection attempts: 5 | Successful connections: 5 | Failed: 0 (0.00%)
        Nping done: 1 IP address pinged in 4.04 seconds
        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response = response.split('\n')
                for line in (response):
                    if "TCP connection attempts:" in line:
                        linedata = line.strip().split('|')
                        # self.debug_print('LINDATA: {}'.format(linedata))
                        response_data['sent'] = linedata[0].split(':')[1].strip()
                        response_data['succeeded'] = linedata[1].split(':')[1].strip()
                        response_data['failed'] = linedata[2].split(':')[1].strip().split(' ')[0].strip()
    
                # Set the summary and response data
                action_result.add_data(response_data)
                # action_result.set_summary({ 'total_hops': len(response_data)})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def _whois_ip(self, param):
        """ Action handler for the 'whois ip' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_WHOIS_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        request_params = {'q' : param.get('ip') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """

        #
        # ARIN WHOIS data and services are subject to the Terms of Use
        # available at: https://www.arin.net/whois_tou.html
        #
        # If you see inaccuracies in the results, please report at
        # https://www.arin.net/public/whoisinaccuracy/index.xhtml
        #
        
        
        #
        # The following results may also be obtained via:
        # https://whois.arin.net/rest/nets;q=8.8.8.8?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2
        #
        
        
        # start
        
        NetRange:       8.0.0.0 - 8.255.255.255
        CIDR:           8.0.0.0/8
        NetName:        LVLT-ORG-8-8
        NetHandle:      NET-8-0-0-0-1
        Parent:          ()
        NetType:        Direct Allocation
        OriginAS:       
        Organization:   Level 3 Communications, Inc. (LVLT)
        RegDate:        1992-12-01
        Updated:        2012-02-24
        Ref:            https://whois.arin.net/rest/net/NET-8-0-0-0-1
        
        
        
        OrgName:        Level 3 Communications, Inc.
        OrgId:          LVLT
        Address:        1025 Eldorado Blvd.
        City:           Broomfield
        StateProv:      CO
        PostalCode:     80021
        Country:        US
        RegDate:        1998-05-22
        Updated:        2012-01-30
        Comment:        ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE
        Ref:            https://whois.arin.net/rest/org/LVLT
        
        
        OrgAbuseHandle: APL8-ARIN
        OrgAbuseName:   Abuse POC LVLT
        OrgAbusePhone:  +1-877-453-8353 
        OrgAbuseEmail:  abuse@level3.com
        OrgAbuseRef:    https://whois.arin.net/rest/poc/APL8-ARIN
        
        OrgTechHandle: IPADD5-ARIN
        OrgTechName:   ipaddressing
        OrgTechPhone:  +1-877-453-8353 
        OrgTechEmail:  ipaddressing@level3.com
        OrgTechRef:    https://whois.arin.net/rest/poc/IPADD5-ARIN
        
        OrgNOCHandle: NOCSU27-ARIN
        OrgNOCName:   NOC Support
        OrgNOCPhone:  +1-877-453-8353 
        OrgNOCEmail:  noc.coreip@level3.com
        OrgNOCRef:    https://whois.arin.net/rest/poc/NOCSU27-ARIN
        
        # end
        
        
        # start
        
        NetRange:       8.8.8.0 - 8.8.8.255
        CIDR:           8.8.8.0/24
        NetName:        LVLT-GOGL-8-8-8
        NetHandle:      NET-8-8-8-0-1
        Parent:         LVLT-ORG-8-8 (NET-8-0-0-0-1)
        NetType:        Reallocated
        OriginAS:       
        Organization:   Google Inc. (GOGL)
        RegDate:        2014-03-14
        Updated:        2014-03-14
        Ref:            https://whois.arin.net/rest/net/NET-8-8-8-0-1
        
        
        
        OrgName:        Google Inc.
        OrgId:          GOGL
        Address:        1600 Amphitheatre Parkway
        City:           Mountain View
        StateProv:      CA
        PostalCode:     94043
        Country:        US
        RegDate:        2000-03-30
        Updated:        2015-11-06
        Ref:            https://whois.arin.net/rest/org/GOGL
        
        
        OrgAbuseHandle: ABUSE5250-ARIN
        OrgAbuseName:   Abuse
        OrgAbusePhone:  +1-650-253-0000 
        OrgAbuseEmail:  network-abuse@google.com
        OrgAbuseRef:    https://whois.arin.net/rest/poc/ABUSE5250-ARIN
        
        OrgTechHandle: ZG39-ARIN
        OrgTechName:   Google Inc
        OrgTechPhone:  +1-650-253-0000 
        OrgTechEmail:  arin-contact@google.com
        OrgTechRef:    https://whois.arin.net/rest/poc/ZG39-ARIN
        
        # end
        
        
        
        #
        # ARIN WHOIS data and services are subject to the Terms of Use
        # available at: https://www.arin.net/whois_tou.html
        #
        # If you see inaccuracies in the results, please report at
        # https://www.arin.net/public/whoisinaccuracy/index.xhtml
        #

        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response = response.strip().split('\n')
                for line in (response):
                    if ": " in line:
                        response_data[line.split(': ', 1)[0].strip().replace(' ', '_')] = line.split(': ', 1)[1].strip()
    
                # Set the summary and response data
                action_result.add_data(response_data)
                # action_result.set_summary({ 'total_hops': len(response_data)})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def _whois_domain(self, param):
        """ Action handler for the 'whois_domain' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_WHOIS_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        request_params = {'q' : param.get('domain') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        
        Whois Server Version 2.0
        
        Domain names in the .com and .net domains can now be registered
        with many different competing registrars. Go to http://www.internic.net
        for detailed information.
        
        Aborting search 50 records found .....
           Server Name: GOOGLE.COM.ACKNOWLEDGES.NON-FREE.COM
           IP Address: 90.0.91.3
           Registrar: NAMESILO, LLC
           Whois Server: whois.namesilo.com
           Referral URL: http://www.namesilo.com
        
        
           Server Name: GOOGLE.COM.AFRICANBATS.ORG
           Registrar: TUCOWS DOMAINS INC.
           Whois Server: whois.tucows.com
           Referral URL: http://www.tucowsdomains.com
                
        
           Server Name: GOOGLE.COM.VN
           Registrar: ONLINENIC, INC.
           Whois Server: whois.onlinenic.com
           Referral URL: http://www.onlinenic.com
        
        
           Domain Name: GOOGLE.COM
           Registrar: MARKMONITOR INC.
           Sponsoring Registrar IANA ID: 292
           Whois Server: whois.markmonitor.com
           Referral URL: http://www.markmonitor.com
           Name Server: NS1.GOOGLE.COM
           Name Server: NS2.GOOGLE.COM
           Name Server: NS3.GOOGLE.COM
           Name Server: NS4.GOOGLE.COM
           Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
           Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
           Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
           Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
           Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
           Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
           Updated Date: 20-jul-2011
           Creation Date: 15-sep-1997
           Expiration Date: 14-sep-2020
        
        >>> Last update of whois database: Fri, 04 Nov 2016 05:01:51 GMT <<<
        
        For more information on Whois status codes, please visit https://icann.org/epp
        
        NOTICE: The expiration date displayed in this record is the date the
        registrar's sponsorship of the domain name registration in the registry is
        currently set to expire. This date does not necessarily reflect the expiration
        date of the domain name registrant's agreement with the sponsoring
        registrar.  Users may consult the sponsoring registrar's Whois database to
        view the registrar's reported date of expiration for this registration.
        
        
        The Registry database contains ONLY .COM, .NET, .EDU domains and
        Registrars.
        Domain Name: google.com
        Registry Domain ID: 2138514_DOMAIN_COM-VRSN
        Registrar WHOIS Server: whois.markmonitor.com
        Registrar URL: http://www.markmonitor.com
        Updated Date: 2015-06-12T10:38:52-0700
        Creation Date: 1997-09-15T00:00:00-0700
        Registrar Registration Expiration Date: 2020-09-13T21:00:00-0700
        Registrar: MarkMonitor, Inc.
        Registrar IANA ID: 292
        Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
        Registrar Abuse Contact Phone: +1.2083895740
        Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
        Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
        Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
        Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
        Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
        Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
        Registry Registrant ID: 
        Registrant Name: Dns Admin
        Registrant Organization: Google Inc.
        Registrant Street: Please contact contact-admin@google.com, 1600 Amphitheatre Parkway
        Registrant City: Mountain View
        Registrant State/Province: CA
        Registrant Postal Code: 94043
        Registrant Country: US
        Registrant Phone: +1.6502530000
        Registrant Phone Ext: 
        Registrant Fax: +1.6506188571
        Registrant Fax Ext: 
        Registrant Email: dns-admin@google.com
        Registry Admin ID: 
        Admin Name: DNS Admin
        Admin Organization: Google Inc.
        Admin Street: 1600 Amphitheatre Parkway
        Admin City: Mountain View
        Admin State/Province: CA
        Admin Postal Code: 94043
        Admin Country: US
        Admin Phone: +1.6506234000
        Admin Phone Ext: 
        Admin Fax: +1.6506188571
        Admin Fax Ext: 
        Admin Email: dns-admin@google.com
        Registry Tech ID: 
        Tech Name: DNS Admin
        Tech Organization: Google Inc.
        Tech Street: 2400 E. Bayshore Pkwy
        Tech City: Mountain View
        Tech State/Province: CA
        Tech Postal Code: 94043
        Tech Country: US
        Tech Phone: +1.6503300100
        Tech Phone Ext: 
        Tech Fax: +1.6506181499
        Tech Fax Ext: 
        Tech Email: dns-admin@google.com
        Name Server: ns2.google.com
        Name Server: ns3.google.com
        Name Server: ns4.google.com
        Name Server: ns1.google.com
        DNSSEC: unsigned
        URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
        >>> Last update of WHOIS database: 2016-11-03T22:01:02-0700 <<<
        
        The Data in MarkMonitor.com's WHOIS database is provided by MarkMonitor.com for
        information purposes, and to assist persons in obtaining information about or
        related to a domain name registration record.  MarkMonitor.com does not guarantee
        its accuracy.  By submitting a WHOIS query, you agree that you will use this Data
        only for lawful purposes and that, under no circumstances will you use this Data to:
         (1) allow, enable, or otherwise support the transmission of mass unsolicited,
             commercial advertising or solicitations via e-mail (spam); or
         (2) enable high volume, automated, electronic processes that apply to
             MarkMonitor.com (or its systems).
        MarkMonitor.com reserves the right to modify these terms at any time.
        By submitting this query, you agree to abide by this policy.
        
        MarkMonitor is the Global Leader in Online Brand Protection.
        
        MarkMonitor Domain Management(TM)
        MarkMonitor Brand Protection(TM)
        MarkMonitor AntiPiracy(TM)
        MarkMonitor AntiFraud(TM)
        Professional and Managed Services
        
        Visit MarkMonitor at http://www.markmonitor.com
        Contact us at +1.8007459229
        In Europe, at +44.02032062220
        
        For more information on Whois status codes, please visit
         https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
        --
        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response = response.strip().split('\n')
                for line in (response):
                    if ": " in line:
                        response_data[line.split(': ', 1)[0].strip().replace(' ', '_')] = line.split(': ', 1)[1].strip()
    
                # Set the summary and response data
                action_result.add_data(response_data)
                # action_result.set_summary({ 'total_hops': len(response_data)})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def _get_http_headers(self, param):
        """ Action handler for the 'get_http_headers' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_HTTPHEADERS_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        request_params = {'q' : param.get('url') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        HTTP/1.1 302 Found
        Location: https://www.google.com/?gws_rd=ssl
        Cache-Control: private
        Content-Type: text/html; charset=UTF-8
        P3P: CP=This is not a P3P policy! See https://www.google.com/support/accounts/answer/151657?hl=en for more info.
        Date: Fri, 04 Nov 2016 05:59:58 GMT
        Server: gws
        Content-Length: 231
        X-XSS-Protection: 1; mode=block
        X-Frame-Options: SAMEORIGIN
        Set-Cookie: NID=90=lGF74xOPS-WohuH24hOd7d-3g858eQoOstprLZTDuxG7PWX4iEfkoHVN0OTfh76r2dZaRcs5GVA9gZEy4Kxz_IZVmhjywzcrXbmXxumDufycZjdC3GCHtWTmYB4tuKRM; expires=Sat, 06-May-2017 05:59:58 GMT; path=/; domain=.google.com; HttpOnly
        
        HTTP/1.1 200 OK
        Date: Fri, 04 Nov 2016 05:59:59 GMT
        Expires: -1
        Cache-Control: private, max-age=0
        Content-Type: text/html; charset=UTF-8
        Strict-Transport-Security: max-age=86400
        P3P: CP=This is not a P3P policy! See https://www.google.com/support/accounts/answer/151657?hl=en for more info.
        Server: gws
        X-XSS-Protection: 1; mode=block
        X-Frame-Options: SAMEORIGIN
        Set-Cookie: NID=90=OVSYFWe4vAEcYCrr6Sm_mNwdBwl3uJCC6FOQHakkiVbzHuOTJLhiFIdMMo_V90V7t7Sdr6VQUAqojFaiLGIrxPM58UrMd630c5AufwCDClqBoVHiN1BeyUnErOUQW4Aj-jc9ZaddeT2Ob0s; expires=Sat, 06-May-2017 05:59:59 GMT; path=/; domain=.google.com; HttpOnly
        Alt-Svc: quic=:443; ma=2592000; v=36,35,34
        Transfer-Encoding: chunked
        Accept-Ranges: none
        Vary: Accept-Encoding
        """
        headerfound = False
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response_headers = response.strip().split('HTTP/')[1:]
                response_data['headers'] = []
                for response2 in response_headers:
                    response2 = response2.strip().split('\n')
                    response_data_temp = {}
                    for line in (response2):
                        if ": " in line:
                            response_data_temp[line.split(': ', 1)[0].strip().replace(' ', '_')] = line.split(': ', 1)[1].strip()
                        elif len(line.split(' ')) > 2:
                            response_data_temp['http_version'] = line.split(' ')[0]
                            response_data_temp['response_code'] = line.split(' ')[1]
                    response_data['headers'].append(response_data_temp)
    
                # Set the summary and response data
                action_result.add_data(response_data)
                action_result.set_summary({ 'header_count': len(response_data['headers'])})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def _get_http_links(self, param):
        """ Action handler for the 'get_http_links' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_PAGELINKS_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        request_params = {'q' : param.get('url') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        http://www.google.com/imghp?hl=en&tab=wi
        http://maps.google.com/maps?hl=en&tab=wl
        https://play.google.com/?hl=en&tab=w8
        http://www.youtube.com/?tab=w1
        http://news.google.com/nwshp?hl=en&tab=wn
        https://mail.google.com/mail/?tab=wm
        https://drive.google.com/?tab=wo
        https://www.google.com/intl/en/options/
        http://www.google.com/history/optout?hl=en
        http://www.google.com/preferences?hl=en
        https://accounts.google.com/ServiceLogin?hl=en&passive=true&continue=http://www.google.com/
        http://www.google.com/search?site=&ie=UTF-8&q=walter+cronkite+journalist&oi=ddle&ct=walter-cronkites-100th-birthday-4805020395503616&hl=en&sa=X&ved=0ahUKEwjxsIbwto7QAhVJfiYKHYn1DP4QPQgC
        http://www.google.com/logos/doodles/2016/walter-cronkites-100th-birthday-4805020395503616.5-hp.gif
        http://www.google.com/advanced_search?hl=en&authuser=0
        http://www.google.com/language_tools?hl=en&authuser=0
        http://www.google.com/intl/en/ads/
        http://www.google.com/services/
        https://plus.google.com/116899029375914044550
        http://www.google.com/intl/en/about.html
        http://www.google.com/intl/en/policies/privacy/
        http://www.google.com/intl/en/policies/terms/
        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response = response.strip().split('\n')
                response_data['urls'] = []
                for line in (response):
                    if "http" in line:
                        response_data['urls'].append({'url' : line })
    
                # Set the summary and response data
                action_result.add_data(response_data)
                action_result.set_summary({ 'total_urls': len(response_data['urls'])})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR


    def _traceroute_host(self, param):
        """ Action handler for the 'run traceroute' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = HACKERTARGET_MTR_URI

        # Progress
        self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # parameters here
        # host - hostname; required.
        if param.get('ip'):
            request_params = {'q' : param.get('ip') }
        else:
            request_params = {'q' : param.get('domain') }

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params=request_params)

        """
        Start: Thu Nov  3 19:27:43 2016
        HOST: whatismyip                     Loss%   Snt   Last   Avg  Best  Wrst StDev
          1.|-- 107.170.238.253                 0.0%     4    2.1   0.9   0.4   2.1   0.6
          2.|-- 138.197.248.214                 0.0%     4    0.4   0.4   0.4   0.4   0.0
          3.|-- as15169.sfmix.org               0.0%     4    2.5   2.6   2.5   2.9   0.0
          4.|-- 108.170.242.81                  0.0%     4    3.1   3.1   3.0   3.2   0.0
          5.|-- 216.239.48.233                  0.0%     4    3.4   3.4   3.4   3.4   0.0
          6.|-- google-public-dns-a.google.com  0.0%     4    2.9   3.0   2.9   3.1   0.0
        """
        if ret_val:
            if 'error: ' in response: # summary has been set to error per rest pull code, exit with success
                return action_result.set_status(phantom.APP_SUCCESS, response)
            else:
                response_data = {'raw' : response }
                response_data['hop'] = {}
                response = response.split('\n')
                for line in (response):
                    if "|--" in line:
                        linedata = " ".join(line.strip().split())
                        lineno = linedata[0].split('.')[0]
                        response_data['hop'][lineno] = {}
                        response_data['hop'][lineno]['raw'] = linedata
                        response_data['hop'][lineno]['host'] = response_data['hop'][lineno]['raw'].split(' ')[1]
                        response_data['hop'][lineno]['loss'] = response_data['hop'][lineno]['raw'].split(' ')[2]
                        response_data['hop'][lineno]['sent'] = response_data['hop'][lineno]['raw'].split(' ')[3]
                        response_data['hop'][lineno]['last'] = response_data['hop'][lineno]['raw'].split(' ')[4]
                        response_data['hop'][lineno]['avg'] = response_data['hop'][lineno]['raw'].split(' ')[5]
                        response_data['hop'][lineno]['best'] = response_data['hop'][lineno]['raw'].split(' ')[6]
                        response_data['hop'][lineno]['worst'] = response_data['hop'][lineno]['raw'].split(' ')[7]
                        response_data['hop'][lineno]['stdev'] = response_data['hop'][lineno]['raw'].split(' ')[8]
                        response_data['hop'][lineno]['hop'] = lineno
    
                # Set the summary and response data
                action_result.add_data(response_data)
                action_result.set_summary({ 'total_hops': len(response_data['hop'])})
    
                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return phantom.APP_ERROR

    def handle_action(self, param):
        """Function that handles all the actions"""

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        # Intialize it to success
        ret_val = phantom.APP_SUCCESS

        #self.debug_print('DEBUG Action: {}'.format(action))
        # Bunch if if..elif to process actions
        if (action == self.ACTION_ID_TRACEROUTE_IP):
            ret_val = self._traceroute_host(param)
        elif (action == self.ACTION_ID_TRACEROUTE_DOMAIN):
            ret_val = self._traceroute_host(param)
        elif (action == self.ACTION_ID_PING_IP):
            ret_val = self._ping_host(param)
        elif (action == self.ACTION_ID_PING_DOMAIN):
            ret_val = self._ping_host(param)
        elif (action == self.ACTION_ID_REVERSE_IP):
            ret_val = self._reverse_domain(param)
        elif (action == self.ACTION_ID_REVERSE_DOMAIN):
            ret_val = self._reverse_domain(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            ret_val = self._whois_ip(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_domain(param)
        elif (action == self.ACTION_ID_GEOLOCATE_IP):
            ret_val = self._geolocate_domain(param)
        elif (action == self.ACTION_ID_GEOLOCATE_DOMAIN):
            ret_val = self._geolocate_domain(param)
        elif (action == self.ACTION_ID_GET_HEADERS):
            ret_val = self._get_http_headers(param)
        elif (action == self.ACTION_ID_GET_LINKS):
            ret_val = self._get_http_links(param)
        
        #self.debug_print('DEBUG: ret_val: {}'.format(ret_val))

        return ret_val

if __name__ == '__main__':
    """ Code that is executed when run in standalone debug mode
    for .e.g:
    python2.7 ./hackertarget.py /tmp/hackertarget.json
    """

    # Imports
    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:

        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        # Create the connector class object
        connector = HackerTargetConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print ret_val

    exit(0)
