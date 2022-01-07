[comment]: # "Auto-generated SOAR connector documentation"
# HackerTarget

Publisher: Splunk  
Connector Version: 2\.0\.4  
Product Vendor: HackerTarget  
Product Name: HackerTarget  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports executing investigative actions to analyze a host

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a HackerTarget asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  optional  | string | Base URL
**api\_key** |  optional  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[get headers](#action-get-headers) - Get HTTP Headers from a URL  
[get links](#action-get-links) - Get HTTP Links from a URL  
[traceroute domain](#action-traceroute-domain) - Traceroute to a domain  
[traceroute ip](#action-traceroute-ip) - Traceoute to an IP  
[reverse domain](#action-reverse-domain) - Find IPs that resolve to this domain  
[reverse ip](#action-reverse-ip) - Find domains that resolve to this IP  
[whois ip](#action-whois-ip) - Execute a whois lookup on the given IP  
[whois domain](#action-whois-domain) - Execute a whois lookup on the given domain  
[ping domain](#action-ping-domain) - Ping a domain  
[ping ip](#action-ping-ip) - Ping an IP  
[geolocate ip](#action-geolocate-ip) - Geolocate an IP  
[geolocate domain](#action-geolocate-domain) - Geolocate a domain  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get headers'
Get HTTP Headers from a URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL ie\. http\://www\.hackertarget\.com | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.headers\.\*\.Accept\-Ranges | string | 
action\_result\.data\.\*\.headers\.\*\.Age | string | 
action\_result\.data\.\*\.headers\.\*\.Alt\-Svc | string | 
action\_result\.data\.\*\.headers\.\*\.Cache\-Control | string | 
action\_result\.data\.\*\.headers\.\*\.Content\-Encoding | string | 
action\_result\.data\.\*\.headers\.\*\.Content\-Length | string | 
action\_result\.data\.\*\.headers\.\*\.Content\-Type | string | 
action\_result\.data\.\*\.headers\.\*\.Date | string | 
action\_result\.data\.\*\.headers\.\*\.Expires | string | 
action\_result\.data\.\*\.headers\.\*\.Last\-Modified | string | 
action\_result\.data\.\*\.headers\.\*\.Location | string |  `url` 
action\_result\.data\.\*\.headers\.\*\.P3P | string | 
action\_result\.data\.\*\.headers\.\*\.Server | string | 
action\_result\.data\.\*\.headers\.\*\.Set\-Cookie | string | 
action\_result\.data\.\*\.headers\.\*\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.headers\.\*\.Transfer\-Encoding | string | 
action\_result\.data\.\*\.headers\.\*\.Vary | string | 
action\_result\.data\.\*\.headers\.\*\.X\-Cache | string | 
action\_result\.data\.\*\.headers\.\*\.X\-Frame\-Options | string | 
action\_result\.data\.\*\.headers\.\*\.X\-XSS\-Protection | string | 
action\_result\.data\.\*\.headers\.\*\.http\_version | string | 
action\_result\.data\.\*\.headers\.\*\.response\_code | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary\.header\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get links'
Get HTTP Links from a URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL ie\. http\://www\.hackertarget\.com | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.raw | string |  `url` 
action\_result\.data\.\*\.urls\.\*\.url | string |  `url` 
action\_result\.summary\.total\_urls | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'traceroute domain'
Traceroute to a domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Host FQDN ie\. www\.hackertarget\.com | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data\.\*\.hop\.\*\.avg | string | 
action\_result\.data\.\*\.hop\.\*\.best | string | 
action\_result\.data\.\*\.hop\.\*\.hop | string | 
action\_result\.data\.\*\.hop\.\*\.host | string |  `domain`  `ip` 
action\_result\.data\.\*\.hop\.\*\.last | string | 
action\_result\.data\.\*\.hop\.\*\.loss | string | 
action\_result\.data\.\*\.hop\.\*\.raw | string | 
action\_result\.data\.\*\.hop\.\*\.sent | string | 
action\_result\.data\.\*\.hop\.\*\.stdev | string | 
action\_result\.data\.\*\.hop\.\*\.worst | string | 
action\_result\.data\.\*\.hop\.1\.avg | string | 
action\_result\.data\.\*\.hop\.1\.best | string | 
action\_result\.data\.\*\.hop\.1\.hop | string | 
action\_result\.data\.\*\.hop\.1\.host | string | 
action\_result\.data\.\*\.hop\.1\.last | string | 
action\_result\.data\.\*\.hop\.1\.loss | string | 
action\_result\.data\.\*\.hop\.1\.raw | string | 
action\_result\.data\.\*\.hop\.1\.sent | string | 
action\_result\.data\.\*\.hop\.1\.stdev | string | 
action\_result\.data\.\*\.hop\.1\.worst | string | 
action\_result\.data\.\*\.hop\.2\.avg | string | 
action\_result\.data\.\*\.hop\.2\.best | string | 
action\_result\.data\.\*\.hop\.2\.hop | string | 
action\_result\.data\.\*\.hop\.2\.host | string | 
action\_result\.data\.\*\.hop\.2\.last | string | 
action\_result\.data\.\*\.hop\.2\.loss | string | 
action\_result\.data\.\*\.hop\.2\.raw | string | 
action\_result\.data\.\*\.hop\.2\.sent | string | 
action\_result\.data\.\*\.hop\.2\.stdev | string | 
action\_result\.data\.\*\.hop\.2\.worst | string | 
action\_result\.data\.\*\.hop\.3\.avg | string | 
action\_result\.data\.\*\.hop\.3\.best | string | 
action\_result\.data\.\*\.hop\.3\.hop | string | 
action\_result\.data\.\*\.hop\.3\.host | string | 
action\_result\.data\.\*\.hop\.3\.last | string | 
action\_result\.data\.\*\.hop\.3\.loss | string | 
action\_result\.data\.\*\.hop\.3\.raw | string | 
action\_result\.data\.\*\.hop\.3\.sent | string | 
action\_result\.data\.\*\.hop\.3\.stdev | string | 
action\_result\.data\.\*\.hop\.3\.worst | string | 
action\_result\.data\.\*\.hop\.4\.avg | string | 
action\_result\.data\.\*\.hop\.4\.best | string | 
action\_result\.data\.\*\.hop\.4\.hop | string | 
action\_result\.data\.\*\.hop\.4\.host | string | 
action\_result\.data\.\*\.hop\.4\.last | string | 
action\_result\.data\.\*\.hop\.4\.loss | string | 
action\_result\.data\.\*\.hop\.4\.raw | string | 
action\_result\.data\.\*\.hop\.4\.sent | string | 
action\_result\.data\.\*\.hop\.4\.stdev | string | 
action\_result\.data\.\*\.hop\.4\.worst | string | 
action\_result\.data\.\*\.hop\.5\.avg | string | 
action\_result\.data\.\*\.hop\.5\.best | string | 
action\_result\.data\.\*\.hop\.5\.hop | string | 
action\_result\.data\.\*\.hop\.5\.host | string | 
action\_result\.data\.\*\.hop\.5\.last | string | 
action\_result\.data\.\*\.hop\.5\.loss | string | 
action\_result\.data\.\*\.hop\.5\.raw | string | 
action\_result\.data\.\*\.hop\.5\.sent | string | 
action\_result\.data\.\*\.hop\.5\.stdev | string | 
action\_result\.data\.\*\.hop\.5\.worst | string | 
action\_result\.data\.\*\.hop\.6\.avg | string | 
action\_result\.data\.\*\.hop\.6\.best | string | 
action\_result\.data\.\*\.hop\.6\.hop | string | 
action\_result\.data\.\*\.hop\.6\.host | string | 
action\_result\.data\.\*\.hop\.6\.last | string | 
action\_result\.data\.\*\.hop\.6\.loss | string | 
action\_result\.data\.\*\.hop\.6\.raw | string | 
action\_result\.data\.\*\.hop\.6\.sent | string | 
action\_result\.data\.\*\.hop\.6\.stdev | string | 
action\_result\.data\.\*\.hop\.6\.worst | string | 
action\_result\.data\.\*\.hop\.7\.avg | string | 
action\_result\.data\.\*\.hop\.7\.best | string | 
action\_result\.data\.\*\.hop\.7\.hop | string | 
action\_result\.data\.\*\.hop\.7\.host | string | 
action\_result\.data\.\*\.hop\.7\.last | string | 
action\_result\.data\.\*\.hop\.7\.loss | string | 
action\_result\.data\.\*\.hop\.7\.raw | string | 
action\_result\.data\.\*\.hop\.7\.sent | string | 
action\_result\.data\.\*\.hop\.7\.stdev | string | 
action\_result\.data\.\*\.hop\.7\.worst | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary\.total\_hops | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'traceroute ip'
Traceoute to an IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | Host ip | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.hop\.\*\.avg | string | 
action\_result\.data\.\*\.hop\.\*\.best | string | 
action\_result\.data\.\*\.hop\.\*\.hop | string | 
action\_result\.data\.\*\.hop\.\*\.host | string |  `domain`  `ip` 
action\_result\.data\.\*\.hop\.\*\.last | string | 
action\_result\.data\.\*\.hop\.\*\.loss | string | 
action\_result\.data\.\*\.hop\.\*\.raw | string | 
action\_result\.data\.\*\.hop\.\*\.sent | string | 
action\_result\.data\.\*\.hop\.\*\.stdev | string | 
action\_result\.data\.\*\.hop\.\*\.worst | string | 
action\_result\.data\.\*\.hop\.1\.avg | string | 
action\_result\.data\.\*\.hop\.1\.best | string | 
action\_result\.data\.\*\.hop\.1\.hop | string | 
action\_result\.data\.\*\.hop\.1\.host | string | 
action\_result\.data\.\*\.hop\.1\.last | string | 
action\_result\.data\.\*\.hop\.1\.loss | string | 
action\_result\.data\.\*\.hop\.1\.raw | string | 
action\_result\.data\.\*\.hop\.1\.sent | string | 
action\_result\.data\.\*\.hop\.1\.stdev | string | 
action\_result\.data\.\*\.hop\.1\.worst | string | 
action\_result\.data\.\*\.hop\.2\.avg | string | 
action\_result\.data\.\*\.hop\.2\.best | string | 
action\_result\.data\.\*\.hop\.2\.hop | string | 
action\_result\.data\.\*\.hop\.2\.host | string |  `ip` 
action\_result\.data\.\*\.hop\.2\.last | string | 
action\_result\.data\.\*\.hop\.2\.loss | string | 
action\_result\.data\.\*\.hop\.2\.raw | string | 
action\_result\.data\.\*\.hop\.2\.sent | string | 
action\_result\.data\.\*\.hop\.2\.stdev | string | 
action\_result\.data\.\*\.hop\.2\.worst | string | 
action\_result\.data\.\*\.hop\.3\.avg | string | 
action\_result\.data\.\*\.hop\.3\.best | string | 
action\_result\.data\.\*\.hop\.3\.hop | string | 
action\_result\.data\.\*\.hop\.3\.host | string |  `ip` 
action\_result\.data\.\*\.hop\.3\.last | string | 
action\_result\.data\.\*\.hop\.3\.loss | string | 
action\_result\.data\.\*\.hop\.3\.raw | string | 
action\_result\.data\.\*\.hop\.3\.sent | string | 
action\_result\.data\.\*\.hop\.3\.stdev | string | 
action\_result\.data\.\*\.hop\.3\.worst | string | 
action\_result\.data\.\*\.hop\.4\.avg | string | 
action\_result\.data\.\*\.hop\.4\.best | string | 
action\_result\.data\.\*\.hop\.4\.hop | string | 
action\_result\.data\.\*\.hop\.4\.host | string | 
action\_result\.data\.\*\.hop\.4\.last | string | 
action\_result\.data\.\*\.hop\.4\.loss | string | 
action\_result\.data\.\*\.hop\.4\.raw | string | 
action\_result\.data\.\*\.hop\.4\.sent | string | 
action\_result\.data\.\*\.hop\.4\.stdev | string | 
action\_result\.data\.\*\.hop\.4\.worst | string | 
action\_result\.data\.\*\.hop\.5\.avg | string | 
action\_result\.data\.\*\.hop\.5\.best | string | 
action\_result\.data\.\*\.hop\.5\.hop | string | 
action\_result\.data\.\*\.hop\.5\.host | string | 
action\_result\.data\.\*\.hop\.5\.last | string | 
action\_result\.data\.\*\.hop\.5\.loss | string | 
action\_result\.data\.\*\.hop\.5\.raw | string | 
action\_result\.data\.\*\.hop\.5\.sent | string | 
action\_result\.data\.\*\.hop\.5\.stdev | string | 
action\_result\.data\.\*\.hop\.5\.worst | string | 
action\_result\.data\.\*\.hop\.6\.avg | string | 
action\_result\.data\.\*\.hop\.6\.best | string | 
action\_result\.data\.\*\.hop\.6\.hop | string | 
action\_result\.data\.\*\.hop\.6\.host | string |  `ip` 
action\_result\.data\.\*\.hop\.6\.last | string | 
action\_result\.data\.\*\.hop\.6\.loss | string | 
action\_result\.data\.\*\.hop\.6\.raw | string | 
action\_result\.data\.\*\.hop\.6\.sent | string | 
action\_result\.data\.\*\.hop\.6\.stdev | string | 
action\_result\.data\.\*\.hop\.6\.worst | string | 
action\_result\.data\.\*\.hop\.7\.avg | string | 
action\_result\.data\.\*\.hop\.7\.best | string | 
action\_result\.data\.\*\.hop\.7\.hop | string | 
action\_result\.data\.\*\.hop\.7\.host | string | 
action\_result\.data\.\*\.hop\.7\.last | string | 
action\_result\.data\.\*\.hop\.7\.loss | string | 
action\_result\.data\.\*\.hop\.7\.raw | string | 
action\_result\.data\.\*\.hop\.7\.sent | string | 
action\_result\.data\.\*\.hop\.7\.stdev | string | 
action\_result\.data\.\*\.hop\.7\.worst | string | 
action\_result\.data\.\*\.hop\.8\.avg | string | 
action\_result\.data\.\*\.hop\.8\.best | string | 
action\_result\.data\.\*\.hop\.8\.hop | string | 
action\_result\.data\.\*\.hop\.8\.host | string | 
action\_result\.data\.\*\.hop\.8\.last | string | 
action\_result\.data\.\*\.hop\.8\.loss | string | 
action\_result\.data\.\*\.hop\.8\.raw | string | 
action\_result\.data\.\*\.hop\.8\.sent | string | 
action\_result\.data\.\*\.hop\.8\.stdev | string | 
action\_result\.data\.\*\.hop\.8\.worst | string | 
action\_result\.data\.\*\.hop\.9\.avg | string | 
action\_result\.data\.\*\.hop\.9\.best | string | 
action\_result\.data\.\*\.hop\.9\.hop | string | 
action\_result\.data\.\*\.hop\.9\.host | string | 
action\_result\.data\.\*\.hop\.9\.last | string | 
action\_result\.data\.\*\.hop\.9\.loss | string | 
action\_result\.data\.\*\.hop\.9\.raw | string | 
action\_result\.data\.\*\.hop\.9\.sent | string | 
action\_result\.data\.\*\.hop\.9\.stdev | string | 
action\_result\.data\.\*\.hop\.9\.worst | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary\.total\_hops | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse domain'
Find IPs that resolve to this domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `url`  `domain`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain`  `host name` 
action\_result\.data\.\*\.domain\_names\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domain\_names\.\*\.ip\_addresses | string |  `ip` 
action\_result\.data\.\*\.domain\_names\.\*\.ip\_count | numeric | 
action\_result\.data\.\*\.ip\_addresses\.\*\.domain\_count | numeric | 
action\_result\.data\.\*\.ip\_addresses\.\*\.ip\_address | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_domains | numeric |  `domain` 
action\_result\.summary\.total\_ips | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse ip'
Find domains that resolve to this IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.domain | string |  `ip`  `domain` 
action\_result\.data\.\*\.ip\_addresses\.\*\.domain\_count | numeric | 
action\_result\.data\.\*\.ip\_addresses\.\*\.ip\_address | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary\.total\_domains | numeric |  `domain` 
action\_result\.summary\.total\_ips | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois ip'
Execute a whois lookup on the given IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.Address | string | 
action\_result\.data\.\*\.CIDR | string | 
action\_result\.data\.\*\.City | string | 
action\_result\.data\.\*\.Comment | string | 
action\_result\.data\.\*\.Country | string | 
action\_result\.data\.\*\.NetHandle | string | 
action\_result\.data\.\*\.NetName | string | 
action\_result\.data\.\*\.NetRange | string | 
action\_result\.data\.\*\.NetType | string | 
action\_result\.data\.\*\.OrgAbuseEmail | string |  `email` 
action\_result\.data\.\*\.OrgAbuseHandle | string | 
action\_result\.data\.\*\.OrgAbuseName | string | 
action\_result\.data\.\*\.OrgAbusePhone | string | 
action\_result\.data\.\*\.OrgAbuseRef | string |  `url` 
action\_result\.data\.\*\.OrgId | string | 
action\_result\.data\.\*\.OrgNOCEmail | string |  `email` 
action\_result\.data\.\*\.OrgNOCHandle | string | 
action\_result\.data\.\*\.OrgNOCName | string | 
action\_result\.data\.\*\.OrgNOCPhone | string | 
action\_result\.data\.\*\.OrgNOCRef | string | 
action\_result\.data\.\*\.OrgName | string | 
action\_result\.data\.\*\.OrgTechEmail | string |  `email` 
action\_result\.data\.\*\.OrgTechHandle | string | 
action\_result\.data\.\*\.OrgTechName | string | 
action\_result\.data\.\*\.OrgTechPhone | string | 
action\_result\.data\.\*\.OrgTechRef | string |  `url` 
action\_result\.data\.\*\.Organization | string | 
action\_result\.data\.\*\.OriginAS | string | 
action\_result\.data\.\*\.Parent | string | 
action\_result\.data\.\*\.PostalCode | string | 
action\_result\.data\.\*\.Ref | string |  `url` 
action\_result\.data\.\*\.RegDate | string | 
action\_result\.data\.\*\.StateProv | string | 
action\_result\.data\.\*\.Updated | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary | string | 
action\_result\.summary\.CIDR | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois domain'
Execute a whois lookup on the given domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.>>>\_Last\_update\_of\_WHOIS\_database | string | 
action\_result\.data\.\*\.>>>\_Last\_update\_of\_whois\_database | string | 
action\_result\.data\.\*\.Admin\_Application\_Purpose | string | 
action\_result\.data\.\*\.Admin\_City | string | 
action\_result\.data\.\*\.Admin\_Country | string | 
action\_result\.data\.\*\.Admin\_Email | string |  `email` 
action\_result\.data\.\*\.Admin\_Name | string | 
action\_result\.data\.\*\.Admin\_Nexus\_Category | string | 
action\_result\.data\.\*\.Admin\_Organization | string | 
action\_result\.data\.\*\.Admin\_Phone | string | 
action\_result\.data\.\*\.Admin\_Postal\_Code | string | 
action\_result\.data\.\*\.Admin\_State/Province | string | 
action\_result\.data\.\*\.Admin\_Street | string | 
action\_result\.data\.\*\.Creation\_Date | string | 
action\_result\.data\.\*\.DNSSEC | string | 
action\_result\.data\.\*\.Domain\_Name | string |  `domain` 
action\_result\.data\.\*\.Domain\_Status | string |  `domain` 
action\_result\.data\.\*\.Expiration\_Date | string | 
action\_result\.data\.\*\.NOTICE | string | 
action\_result\.data\.\*\.Name\_Server | string | 
action\_result\.data\.\*\.Please\_note | string | 
action\_result\.data\.\*\.Referral\_URL | string |  `url` 
action\_result\.data\.\*\.Registrant\_Application\_Purpose | string | 
action\_result\.data\.\*\.Registrant\_City | string | 
action\_result\.data\.\*\.Registrant\_Country | string | 
action\_result\.data\.\*\.Registrant\_Email | string |  `email` 
action\_result\.data\.\*\.Registrant\_Name | string | 
action\_result\.data\.\*\.Registrant\_Nexus\_Category | string | 
action\_result\.data\.\*\.Registrant\_Organization | string | 
action\_result\.data\.\*\.Registrant\_Phone | string | 
action\_result\.data\.\*\.Registrant\_Postal\_Code | string | 
action\_result\.data\.\*\.Registrant\_State/Province | string | 
action\_result\.data\.\*\.Registrant\_Street | string | 
action\_result\.data\.\*\.Registrar | string | 
action\_result\.data\.\*\.Registrar\_Abuse\_Contact\_Email | string |  `email` 
action\_result\.data\.\*\.Registrar\_Abuse\_Contact\_Phone | string | 
action\_result\.data\.\*\.Registrar\_IANA\_ID | string | 
action\_result\.data\.\*\.Registrar\_URL | string |  `url` 
action\_result\.data\.\*\.Registrar\_WHOIS\_Server | string | 
action\_result\.data\.\*\.Registry\_Admin\_ID | string | 
action\_result\.data\.\*\.Registry\_Domain\_ID | string |  `domain` 
action\_result\.data\.\*\.Registry\_Expiry\_Date | string | 
action\_result\.data\.\*\.Registry\_Registrant\_ID | string | 
action\_result\.data\.\*\.Registry\_Tech\_ID | string | 
action\_result\.data\.\*\.Sponsoring\_Registrar\_IANA\_ID | string | 
action\_result\.data\.\*\.Status | string | 
action\_result\.data\.\*\.Tech\_Application\_Purpose | string | 
action\_result\.data\.\*\.Tech\_City | string | 
action\_result\.data\.\*\.Tech\_Country | string | 
action\_result\.data\.\*\.Tech\_Email | string |  `email` 
action\_result\.data\.\*\.Tech\_Name | string | 
action\_result\.data\.\*\.Tech\_Nexus\_Category | string | 
action\_result\.data\.\*\.Tech\_Organization | string | 
action\_result\.data\.\*\.Tech\_Phone | string | 
action\_result\.data\.\*\.Tech\_Postal\_Code | string | 
action\_result\.data\.\*\.Tech\_State/Province | string | 
action\_result\.data\.\*\.Tech\_Street | string | 
action\_result\.data\.\*\.URL\_of\_the\_ICANN\_Whois\_Inaccuracy\_Complaint\_Form | string |  `url` 
action\_result\.data\.\*\.Updated\_Date | string | 
action\_result\.data\.\*\.Whois\_Server | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.summary | string | 
action\_result\.summary\.Domain | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ping domain'
Ping a domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Host FQDN such as www\.hackertarget\.com | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.failed | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.sent | string | 
action\_result\.data\.\*\.succeeded | string | 
action\_result\.summary | string | 
action\_result\.summary\.failed | string | 
action\_result\.summary\.received | string | 
action\_result\.summary\.sent | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ping ip'
Ping an IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | Host ip | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.failed | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.sent | string | 
action\_result\.data\.\*\.succeeded | string | 
action\_result\.summary | string | 
action\_result\.summary\.failed | string | 
action\_result\.summary\.received | string | 
action\_result\.summary\.sent | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'geolocate ip'
Geolocate an IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | Host ip | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.city\_name | string | 
action\_result\.data\.\*\.country\_name | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.state\_name | string | 
action\_result\.summary | string | 
action\_result\.summary\.latitude | string | 
action\_result\.summary\.longitude | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'geolocate domain'
Geolocate a domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Host fqdn ie\. www\.hackertarget\.com | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data\.\*\.city\_name | string | 
action\_result\.data\.\*\.country\_name | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.state\_name | string | 
action\_result\.summary | string | 
action\_result\.summary\.latitude | string | 
action\_result\.summary\.longitude | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 