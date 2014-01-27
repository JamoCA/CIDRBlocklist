<cfcomponent output="false">
	<!--- CIDRBlockList is a ColdFusion library to filter IPs based on CIDR block data.
.
		http://www.ipdeny.com/ipblocks/
		https://www.countryipblocks.net/country_selection.php

		http://www.find-ip-address.org/ip-country/
		http://www.wizcrafts.net/chinese-blocklist.html
		http://www.wizcrafts.net/exploited-servers-blocklist.html
		http://www.wizcrafts.net/nigerian-blocklist.html
		http://www.wizcrafts.net/russian-blocklist.html
		http://www.wizcrafts.net/lacnic-blocklist.html
		
		Author: James Moberg, james@ssmedia.com
		Version: 1.1
		Release Date: 12/30/2013
		Last Updated: 1/2/2014
	--->

<cfset variables.BlockLists = StructNew()>
<cfset variables.DefaultCIDRFile = "#GetDirectoryFromPath(GetCurrentTemplatePath())#CIDRBlockList.txt">
<cfset variables.Stats = StructNew()>
	
<cffunction name="init" access="public" returntype="any" output="false" hint="initiates instance of CIDRBlockList">
	<cfargument name="CIDRFile" type="string" default="#variables.DefaultCIDRFile#" hint="Pathname to text file with CIDR data">
	<cfset var i = "">
	<cfset var CIDRcount = 0>
	<cfset variables.BlockLists = ReadCIDRFile(arguments.CIDRFile)>
	<cfloop collection="#variables.BlockLists#" item="i">
		<cfset CIDRcount = CIDRcount + arraylen(variables.BlockLists[i])>
	</cfloop>
	<cfset variables.Stats["InitializedDateTime"] = now()>
	<cfset variables.Stats["LastHitDateTime"] = "">
	<cfset variables.Stats["SearchCount"] = 0>
	<cfset variables.Stats["HitCount"] = 0>
	<cfset variables.Stats["CIDRCount"] = CIDRcount>
	<cfset variables.Stats["Filename"] = arguments.CIDRFile>
	<cfset variables.Stats["FileLastModifiedDate"] = "">
	<cfif fileexists(arguments.CIDRFile)>
		<cfset variables.Stats["FileLastModifiedDate"] = GetFileInfo(arguments.CIDRFile).LastModified>
	</cfif>
	<cfreturn this>
</cffunction>

<cffunction name="ReadCIDRFile" access="private" output="false" returntype="struct" hint="I return a struct with arrays of CIDR ranges">
	<cfargument name="BlockFile" type="string" default="#variables.DefaultCIDRFile#" hint="The file to read.">
	<CFSET var Data = structnew()>
	<CFSET var CIDRArray = arraynew(1)>
	<CFSET var CIDRData = "">
	<CFSET var thisCIDR = arraynew(1)>
	<cfif fileexists(arguments.BlockFile)>
		<cffile action="READ" file="#arguments.BlockFile#" variable="CIDRData">
		<cfset CIDRArray = REGet(CIDRData, "\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))?\b")>
		<cfloop array="#CIDRArray#" index="thisCIDR">
			<cfif not structkeyexists(Data, val(gettoken(ThisCIDR,1,".")))>
				<cfset data[val(gettoken(ThisCIDR,1,"."))] = arraynew(1)>
			</cfif>
			<cfset arrayappend(Data[val(gettoken(ThisCIDR,1,"."))], trim(ThisCIDR))>
		</cfloop>
	</cfif>
	<cfreturn Data>
</cffunction>

<cffunction name="GetStats" access="public" returntype="struct" hint="Return count of number of CIDR values">
	<cfreturn variables.Stats>
</cffunction>

<!--- 8/13/2010 http://www.cflib.org/udf/REGet --->	
<cffunction name="REGet" access="private" returntype="array" output="false" hint="generate array of matched regex values">
	<cfargument name="str" type="string" default="" hint="The string to parse">
	<cfargument name="regexStr" type="string" default="" hint="The regex">
	<cfset var results = arraynew(1)>
	<cfset var test = refind(arguments.regexStr, arguments.str, 1, 1)>
	<cfset var pos = test.pos[1]>
	<cfset var oldpos = 1>
	<cfloop condition="#pos# gt 0">
		<cfset arrayAppend(results, mid(arguments.str, pos, test.len[1]))>
		<cfset oldpos = pos + test.len[1]>
		<cfset test = refind(arguments.regexStr, arguments.str, oldpos, 1)>
		<cfset pos = test.pos[1]>
	</CFLOOP>
	<cfreturn results>
</cffunction>
	
<!--- http://tech.groups.yahoo.com/group/fusebox5/message/2089 ---->
<cffunction name="isWithinCIDR" access="private" output="false" returntype="boolean" hint="I test if an IP address falls within the given CIDR range.">
	<cfargument name="CIDR" required="true" type="string" hint="A CIDR address range in the form of AAA.BBB.CCC.DDD/xx">
	<cfargument name="TestIP" required="true" type="string" hint="An IP address to test.">
	<cfset var CIDRParts = ListToArray(arguments.CIDR, "/")>
	<cfset var CIDRAddress = ListToArray(CIDRParts[1], ".")>
	<cfset var CIDRMask = 32>
	<cfset var TestIPAddress = ListToArray(arguments.TestIP, ".")>
	<cfset var CIDRRealAddress = 0>
	<cfset var CIDRRealMask = 0>
	<cfset var TestRealAddress = 0>
	<cfset var TestIPA = 0>
	<cfset var TestIPB = 0>
	<cfset var CidrA = 0>
	<cfset var CidrB = 0>
	<cfset var MaskA = 0>
	<cfset var MaskB = 0>
	<cfset var x = "">
	<CFIF ArrayLen(CIDRParts) EQ 2 AND VAL(CIDRParts[2]) GT 1 AND VAL(CIDRParts[2]) LT 33>
		<cfset CIDRMask = CIDRParts[2]>	
	</CFIF>

	<!--- Get the integer the CIDR core address represents --->
	<cfset CIDRRealAddress = CIDRAddress[4]>
	<cfset CIDRRealAddress = CIDRRealAddress + CIDRAddress[3] * 256> <!--- 2^8 --->
	<cfset CIDRRealAddress = CIDRRealAddress + CIDRAddress[2] * 65536> <!--- 2^16 --->
	<cfset CIDRRealAddress = CIDRRealAddress + CIDRAddress[1] * 16777216> <!--- 2^24 --->
 
	<!--- Get the integer representation of the test IP address --->
	<cfset TestRealAddress = TestIPAddress[4]>
	<cfset TestRealAddress = TestRealAddress + TestIPAddress[3] * 256> <!--- 2^8 --->
	<cfset TestRealAddress = TestRealAddress + TestIPAddress[2] * 65536> <!--- 2^16 --->
	<cfset TestRealAddress = TestRealAddress + TestIPAddress[1] * 16777216> <!--- 2^24 --->
 
	<!--- Get the integer representation of the CIDR mask --->
	<cfloop from="1" to="#CIDRMask#" index="x">
		<cfset CIDRRealMask = CIDRRealMask + 2^(32-x) >
	</cfloop>
 
	<!--- CF's BitAnd() cannot handle 32-bit unsigned integers, we will
	break these addresses into numbers denoting their left and right half bits --->
	<!--- Just the left 16 bits --->
	<cfset CidrA = int(CIDRRealAddress / 65536)>
	<cfset TestIPA = int(TestRealAddress / 65536)>
	<cfset MaskA = int(CIDRRealMask / 65536)>
	<!--- Just the right 16 bits --->
	<!--- Much more efficient would be to use "mod 65536" but even this does not support unsigned integers --->
	<cfset CidrB = CIDRRealAddress - (CidrA * 65536)>
	<cfset TestIPB = TestRealAddress - (TestIPA * 65536)>
	<cfset MaskB = CIDRRealMask - (MaskA * 65536)>
 
	<cfif BitAnd(CidrA, MaskA) eq BitAnd(TestIPA, MaskA) AND BitAnd(CidrB, MaskB) eq BitAnd(TestIPB, MaskB)>
		<cfreturn true>
	<cfelse>
		<cfreturn false>
	</cfif>
</cffunction>


<!--- Written by Joseph Lamoree. Modified by Sami Hoda. http://pastebin.com/TgnSG7iL  --->
<cffunction name="isIPV4" returntype="boolean" access="public" output="false">
	<cfargument name="ip" type="string" required="true">
	<cfset var ba = listToArray(trim(arguments.ip), ".")>
	<cfset var b = "">
	<cfif refind("[^0-9\.]", trim(arguments.ip)) GT 0>
		<cfreturn false>
	<!--- Should have four bytes --->
	<cfelseif arraylen(ba) neq 4>
		<cfreturn false>
	<!--- First and last bytes should be non-zero --->
	<cfelseif val(ba[1]) eq 0 or val(ba[4]) eq 0>
		<cfreturn false>
	<!--- Not all bytes should be 255 --->
	<cfelseif (val(ba[1]) eq 255) and (val(ba[2]) eq 255) and (val(ba[3]) eq 255) and (val(ba[4]) eq 255)>
		<cfreturn false>
	</cfif>
	<cfloop array="#ba#" index="b">
		<!--- No bytes should have leading zeros / No bytes should be greater than 255 --->
		<cfif (len(b) gt 1 and left(b, 1) eq 0) OR val(b) gt 255>
			<cfreturn false>
		</cfif>
	</cfloop>
	<cfreturn true>
</cffunction>

<cffunction name="CheckIP" access="public" output="false" returntype="boolean" hint="Checks IP">
	<cfargument name="IPAddress" type="string" required="true" hint="The IP Address to search for.">
	<cfset var IsFound = false>
	<cfset variables.Stats["SearchCount"] = variables.Stats["SearchCount"] + 1>
	<cfif not isIPV4(arguments.IPAddress)>
		<cfreturn false>
	</cfif>
	<cfif not StructKeyExists(variables.BlockLists, gettoken(arguments.IPAddress,1,"."))>
		<cfreturn false>
	</cfif>
	<cfif isarray(variables.BlockLists[gettoken(arguments.IPAddress,1,".")])>
		<cfloop array="#variables.BlockLists[gettoken(arguments.IPAddress,1,".")]#" index="thisCIDR">
			<cfif not isfound and isWithinCIDR(thisCIDR, arguments.IPAddress)>
				<cfset variables.Stats["HitCount"] = variables.Stats["HitCount"] + 1>
				<cfset variables.Stats["LastHitDateTime"] = now()>
				<cfset IsFound = true>
				<cfbreak>
			</cfif>
		</cfloop>
	</cfif>
	<cfreturn IsFound>
</cffunction>
	
</cfcomponent>