**Unreleased**

* Restricted all downloaded filenames to safe leaves within the Vault staging directory (PSAAS-30461).
* Parsed and sanitized Content-Disposition report filenames before writing them to disk (PSAAS-31122).
* Escaped check-status widget values before embedding them in JavaScript (PSAAS-30932).
* Escaped every dynamic context-menu value in the connector widgets (PSAAS-31197).
* Reported incomplete analyses and report-retrieval failures as detonation errors (PSAAS-31796).
* Derived reputation from the worst completed run and returned unknown for missing verdicts (PSAAS-32232).
* Marked report and PCAP downloads as mutating because they write files to the SOAR vault (PSAAS-31575).
