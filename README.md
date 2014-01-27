CIDRBlockList
=========

CIDRBlockList is a ColdFusion library to filter IPs based on CIDR block data.

  - Read+parse a flat text file with CIDR IP address data
  - Identify whether IP is within CIDR ranges (true/false)
  - Write your own rules

Version
----

1.1

CIDR Data
-----------
Create your own CIDR file. IP ranges can be identified by going to:

* http://www.find-ip-address.org/ip-country/
* http://www.wizcrafts.net/exploited-servers-blocklist.html
* http://www.wizcrafts.net/lacnic-blocklist.html

Initialization
--------------
Initialize the library and read/parse the CIDR data file. (Currently named "CIDRBlocklist.txt in the same sub-directory as library.)
```cf
<CFIF NOT StructKeyExists(application, "CIDRBlockList") OR StructKeyExists(URL, "refreshCIDR")>
	<CFSET application.CIDRBlockList = createObject("component", "CIDRBlockList").init()>
	<!--- Or pass specific CIDR data file 
	<CFSET application.CIDRBlockList = createObject("component", "CIDRBlockList").init("#ThisProjectDir#CIDRBlocklist.txt")>
	--->
</CFIF>
```

Sample Use
----------
```cf
<cfif application.CIDRBlockList.CheckIP(CGI.Remote_Addr)>
    <!--- IP is found within CIDR ranges. Switch to a simple message --->
	<p>To make a donation, please contact us offline at 555-555-5555.</p>
<cfelse>
    <!--- Non-Blocked IP.  Show form or information --->
    <cfinclude template="./donationform.cfm">
</cfif>
```

View Stats
----------
```cf
<CFDUMP VAR="#Application.CIDRBlockList.GetStats()#">
```
