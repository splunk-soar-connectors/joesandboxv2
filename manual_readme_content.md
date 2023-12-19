[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
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
