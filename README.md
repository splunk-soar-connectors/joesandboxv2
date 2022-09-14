[comment]: # "Auto-generated SOAR connector documentation"
# Joe Sandbox v2

Publisher: Splunk  
Connector Version: 2\.1\.0  
Product Vendor: Joe Security LLC  
Product Name: Joe Sandbox v2  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This app supports executing investigative actions to analyze files and URLs on Joe Sandbox

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The report_cache parameter behaves differently for the detonate file and detonate url actions. These
differences are outlined below.  
  
**Detonate File**

-   If caching is enabled and cookbook is provided then the caching is ignored and a new detonation
    analysis process is spawned
-   If caching is enabled and cookbook is not provided then the analysis report of the latest
    spawned process on Joe Sandbox for the provided file hash, is returned
-   If caching is not enabled then always a new detonation analysis process is spawned

**Detonate URL**

-   If caching is enabled then the analysis report of the latest spawned process on Joe Sandbox for
    the provided URL, is returned
-   If caching is not enabled then always a new detonation analysis process is spawned


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Joe Sandbox v2 asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Base URL of Joe Sandbox API
**verify\_ssl** |  optional  | boolean | Verify Joe Sandbox Certificate
**api\_key** |  required  | password | API Key
**timeout** |  optional  | numeric | Detonation timeout \(30\-300 seconds\)
**analysis\_time** |  optional  | numeric | Maximum time to complete detonation analysis \(30\-300 seconds\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[detonate file](#action-detonate-file) - Retrieve detonation analysis results for file  
[get pcap](#action-get-pcap) - Download the pcap file and add it to the vault  
[get report](#action-get-report) - Download the detonation report and add it to the vault  
[check status](#action-check-status) - Check status of sample file or URL submitted for analysis  
[detonate url](#action-detonate-url) - Retrieve detonation analysis results for URL  
[url reputation](#action-url-reputation) - Query Joe Sandbox for URL reputation  
[file reputation](#action-file-reputation) - Query Joe Sandbox for file reputation  
[list cookbooks](#action-list-cookbooks) - List all cookbooks  
[get cookbook](#action-get-cookbook) - Get a cookbook and add it to vault  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'detonate file'
Retrieve detonation analysis results for file

Type: **investigate**  
Read only: **True**

If report\_cache is enabled, action checks the cache for existing reports before running a full analysis and returns the latest analysis report from the cache\. If disabled, it always spawns a new analysis\. If action is unable to find the file from vault using cookbook\_vault\_id, then action will submit analysis without cookbook parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `vault id`  `sha1` 
**cookbook\_vault\_id** |  optional  | Vault ID of cookbook script | string |  `vault id`  `sha1` 
**internet\_access** |  optional  | Allow full internet access | boolean | 
**report\_cache** |  optional  | Enable the report cache | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cookbook\_vault\_id | string |  `vault id`  `sha1` 
action\_result\.parameter\.internet\_access | boolean | 
action\_result\.parameter\.report\_cache | boolean | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.entropy | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.filename | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.filesize | numeric |  `file size` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.filetype | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.md5 | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.ole\.\@arrayTag | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.ole\.\@doctype | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.ole\.\@olefiles | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.ole\.archive\.zip | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.preview | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.sha512 | string |  `sha512` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.ssdeep | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.submissionpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.trid\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.analysisstopreason | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.arch | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.countrycode | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.decenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.duration | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.egaenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existingdriver | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existinginjectprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existingprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.hvm | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.hypermodeon | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.id | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.inetsimip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.javatraceenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.jbxviewon | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.jsinstrenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.newdrivers | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.newprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.product | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.reporttype | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.scaeenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.startdate | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.starttime | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.systemdescription | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.cookbook | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.sample | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.submissionpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.url | string |  `url` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.vbainstrenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.version | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.$ | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.\@count | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.\@name | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.clean | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.detection | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.malicious | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.maxScore | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.minScore | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.score | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.suspicious | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.unknown | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.whitelisted | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.class | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.cmdline | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.date | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.isadmin | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.isdropped | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.md5 | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.modulebase | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.modulesize | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.name | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.parentpid | numeric |  `pid` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.path | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.pid | numeric |  `pid` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.reason | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.reputation | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.size | numeric |  `file size` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.targetid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.time | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.wow64 | boolean | 
action\_result\.data\.\*\.sample\_status\.analysisid | string | 
action\_result\.data\.\*\.sample\_status\.duration | numeric | 
action\_result\.data\.\*\.sample\_status\.filename | string |  `file name` 
action\_result\.data\.\*\.sample\_status\.md5 | string |  `md5` 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.detection | string | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.error | string | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.system | string | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.yara | boolean | 
action\_result\.data\.\*\.sample\_status\.scriptname | string |  `file name` 
action\_result\.data\.\*\.sample\_status\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sample\_status\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sample\_status\.status | string | 
action\_result\.data\.\*\.sample\_status\.time | string | 
action\_result\.data\.\*\.sample\_status\.webid | string |  `joesandbox task id` 
action\_result\.summary\.analysis\_status | string | 
action\_result\.summary\.webid | string |  `joesandbox task id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get pcap'
Download the pcap file and add it to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Web ID of JoeSandbox analysis process | string |  `joesandbox task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `joesandbox task id` 
action\_result\.data\.\*\.report\_file\_name | string |  `file name` 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.report\_availability | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Download the detonation report and add it to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Web ID of JoeSandbox analysis process | string |  `joesandbox task id` 
**type** |  required  | Type of report | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `joesandbox task id` 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.download\_report\_details\.report\_file\_name | string |  `file name` 
action\_result\.data\.\*\.download\_report\_details\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@active | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@currentpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@email | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@malicious | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@name | string |  `domain` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@nameservers | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@registrar | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@reputation | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@targetid | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@dump | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@encrypted | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@entropy | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@file | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@id | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@malicious | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@process | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@reputation | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@size | string |  `file size` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@targetid | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@type | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@whitelisted | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.value\.\*\.$ | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.value\.\*\.\@algo | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.yara\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.entropy | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.filename | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.filesize | numeric |  `file size` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.filetype | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.md5 | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.checksum | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.checksumcalced | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.datadirs\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.datadirs\.datadir\.\*\.address | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.datadirs\.datadir\.\*\.insection | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.datadirs\.datadir\.\*\.name | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.datadirs\.datadir\.\*\.size | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.dllcharacteristics | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypoint | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypointdata | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypointdis\.instr\.\*\.data | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypointdis\.instr\.\*\.len | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypointdis\.instr\.\*\.opcode | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypointdis\.instr\.\*\.type | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.entrypointsection | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.exports | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.fileversion\.major | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.fileversion\.minor | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.imagebase | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.imagefilecharacteristics | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.imphash | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.imports\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.imports\.import\.\*\.dllname | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.imports\.import\.\*\.functions | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.origins\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.origins\.origin\.country | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.origins\.origin\.flag | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.origins\.origin\.language | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.osversion\.major | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.osversion\.minor | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.resource\.\*\.country | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.resource\.\*\.language | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.resource\.\*\.name | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.resource\.\*\.rva | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.resource\.\*\.size | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.resources\.resource\.\*\.type | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.richheaders\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.richheaders\.richheader\.\*\.info | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.characteristics | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.entropy | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.name | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.rawaddr | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.rawsize | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.type | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.virtaddr | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.virtsize | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.xoredpe | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.sections\.section\.\*\.zlibcomplexity | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.signature\.signed | boolean | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.subsystem | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.subsystemversion\.major | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.subsystemversion\.minor | numeric | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.timestamp | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.tls | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.versions\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.versions\.version\.\*\.name | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.pe\.versions\.version\.\*\.value | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.preview | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.sha512 | string |  `sha512` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.ssdeep | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.submissionpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.fileinfo\.trid\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo\.trid\.def | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.analysisstopreason | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.arch | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.countrycode | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.decenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.duration | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.egaenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existingdriver | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existinginjectprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existingprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.hvm | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.hypermodeon | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.id | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.inetsimip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.javatraceenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.jbxviewon | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.jsinstrenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.newdrivers | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.newprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.product | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.reporttype | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.scaeenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.startdate | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.starttime | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.systemdescription | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.cookbook | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.sample | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.submissionpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.url | string |  `url` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.vbainstrenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.version | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@asnname | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@asnnbr | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@country | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@countrycode | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@countrycode2l | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@currentpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@malicious | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@openports | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@pingable | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@private | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@targetid | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.$ | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.\@count | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.\@name | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.clean | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.detection | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.malicious | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.maxScore | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.minScore | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.score | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.suspicious | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.unknown | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.whitelisted | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.class | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.cmdline | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.date | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.isadmin | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.isdropped | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.md5 | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.modulebase | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.modulesize | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.name | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.parentpid | numeric |  `pid` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.path | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.pid | numeric |  `pid` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.reason | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.reputation | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.size | numeric |  `file size` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.targetid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.time | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.wow64 | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.count | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.id | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.path | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.ret | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.status | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.symbol | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.threadid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.count | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.id | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.name | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.newdata | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.newdataascii | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.olddata | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.path | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.ret | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.status | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.symbol | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.threadid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.type | string | 
action\_result\.summary\.report\_availability | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'check status'
Check status of sample file or URL submitted for analysis

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Web ID of JoeSandbox analysis process | string |  `joesandbox task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `joesandbox task id` 
action\_result\.data\.\*\.analysisid | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.filename | string |  `file name` 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.runs\.\*\.detection | string | 
action\_result\.data\.\*\.runs\.\*\.error | string | 
action\_result\.data\.\*\.runs\.\*\.system | string | 
action\_result\.data\.\*\.runs\.\*\.yara | boolean | 
action\_result\.data\.\*\.scriptname | string |  `file name` 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.time | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.webid | string |  `joesandbox task id` 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Retrieve detonation analysis results for URL

Type: **investigate**  
Read only: **True**

If report\_cache is enabled, action checks the cache for existing reports before running a full analysis and returns the latest analysis report from the cache\. If disabled, it always spawns a new analysis\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to be analyzed | string |  `url`  `domain` 
**internet\_access** |  optional  | Allow full internet access | boolean | 
**report\_cache** |  optional  | Enable the report cache | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.internet\_access | boolean | 
action\_result\.parameter\.placeholder | string | 
action\_result\.parameter\.report\_cache | boolean | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@active | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@currentpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@email | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@malicious | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@name | string |  `domain` 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@nameservers | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@registrar | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@reputation | string | 
action\_result\.data\.\*\.sample\_details\.domaininfo\.domain\.\*\.\@targetid | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@dump | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@encrypted | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@entropy | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@file | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@id | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@malicious | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@process | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@reputation | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@size | string |  `file size` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@targetid | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@type | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.\@whitelisted | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.value\.\*\.$ | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.value\.\*\.\@algo | string | 
action\_result\.data\.\*\.sample\_details\.droppedinfo\.hash\.\*\.yara\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.fileinfo | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.analysisstopreason | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.arch | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.countrycode | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.decenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.duration | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.egaenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existingdriver | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existinginjectprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.existingprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.hvm | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.hypermodeon | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.id | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.inetsimip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.javatraceenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.jbxviewon | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.jsinstrenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.newdrivers | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.newprocesses | numeric | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.product | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.reporttype | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.scaeenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.startdate | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.starttime | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.systemdescription | string | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.cookbook | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.sample | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.submissionpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.target\.url | string |  `url` 
action\_result\.data\.\*\.sample\_details\.generalinfo\.vbainstrenabled | boolean | 
action\_result\.data\.\*\.sample\_details\.generalinfo\.version | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@asnname | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@asnnbr | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@country | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@countrycode | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@countrycode2l | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@currentpath | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@malicious | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@openports | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@pingable | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@private | string | 
action\_result\.data\.\*\.sample\_details\.ipinfo\.ip\.\*\.\@targetid | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.\@isArray | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.$ | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.\@count | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.\@name | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.clean | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.detection | string | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.malicious | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.maxScore | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.minScore | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.score | numeric | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.suspicious | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.unknown | boolean | 
action\_result\.data\.\*\.sample\_details\.signaturedetections\.strategy\.\*\.whitelisted | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.cmdline | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.date | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.isadmin | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.isdropped | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.md5 | string |  `md5` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.modulebase | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.modulesize | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.name | string |  `file name` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.parentpid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.path | string |  `file path` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.pid | numeric |  `pid` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.reason | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.reputation | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.size | numeric |  `file size` 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.targetid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.time | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.general\.wow64 | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.count | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.id | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.path | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.ret | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.status | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.symbol | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyCreated\.\*\.threadid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.count | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.id | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.iswindows | boolean | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.name | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.newdata | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.newdataascii | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.olddata | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.path | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.ret | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.status | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.symbol | string | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.threadid | numeric | 
action\_result\.data\.\*\.sample\_details\.system\_behavior\.\*\.registryactivities\.keyValueModified\.\*\.type | string | 
action\_result\.data\.\*\.sample\_status\.analysisid | string | 
action\_result\.data\.\*\.sample\_status\.duration | numeric | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.detection | string | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.error | string | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.system | string | 
action\_result\.data\.\*\.sample\_status\.runs\.\*\.yara | boolean | 
action\_result\.data\.\*\.sample\_status\.scriptname | string |  `file name` 
action\_result\.data\.\*\.sample\_status\.status | string | 
action\_result\.data\.\*\.sample\_status\.time | string | 
action\_result\.data\.\*\.sample\_status\.url | string |  `url` 
action\_result\.data\.\*\.sample\_status\.webid | string |  `joesandbox task id` 
action\_result\.summary\.analysis\_status | string | 
action\_result\.summary\.webid | string |  `joesandbox task id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Query Joe Sandbox for URL reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.analysisid | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.reputation\_label | string | 
action\_result\.data\.\*\.runs\.\*\.detection | string | 
action\_result\.data\.\*\.runs\.\*\.error | string | 
action\_result\.data\.\*\.runs\.\*\.system | string | 
action\_result\.data\.\*\.runs\.\*\.yara | boolean | 
action\_result\.data\.\*\.scriptname | string |  `file name` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.time | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.webid | string |  `joesandbox task id` 
action\_result\.summary\.reputation\_label | string | 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Query Joe Sandbox for file reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File Hash \(MD5, SHA\-1 or SHA\-256\) | string |  `hash`  `md5`  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256` 
action\_result\.data\.\*\.analysisid | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.filename | string |  `file name` 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.reputation\_label | string | 
action\_result\.data\.\*\.runs\.\*\.detection | string | 
action\_result\.data\.\*\.runs\.\*\.error | string | 
action\_result\.data\.\*\.runs\.\*\.system | string | 
action\_result\.data\.\*\.runs\.\*\.yara | boolean | 
action\_result\.data\.\*\.scriptname | string |  `file name` 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.time | string | 
action\_result\.data\.\*\.webid | string |  `joesandbox task id` 
action\_result\.summary\.reputation\_label | string | 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list cookbooks'
List all cookbooks

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.id | string |  `joesandbox cookbook id` 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.total\_cookbooks | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get cookbook'
Get a cookbook and add it to vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Cookbook ID | string |  `joesandbox cookbook id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `joesandbox cookbook id` 
action\_result\.data\.\*\.code | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.cookbook\_file\_name | string |  `file name` 
action\_result\.data\.\*\.cookbook\_vault\_id | string |  `vault id` 
action\_result\.data\.\*\.id | string |  `joesandbox cookbook id` 
action\_result\.data\.\*\.name | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 