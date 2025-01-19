# Go Hunt

## Collection of commands

### [httpx](https://github.com/projectdiscovery/httpx) [shodan](https://cli.shodan.io/) [katana](https://github.com/projectdiscovery/katana) [dnsx](https://github.com/projectdiscovery/dnsx) [HEDnsExtractor](https://github.com/HuntDownProject/HEDnsExtractor) [nuclei](https://github.com/projectdiscovery/nuclei) [proxify](https://github.com/projectdiscovery/proxify) [chaos](https://github.com/projectdiscovery/chaos-client) [CDNcheck](https://github.com/projectdiscovery/cdncheck) [tlsx](https://github.com/projectdiscovery/tlsx) [asnmap](https://github.com/projectdiscovery/asnmap)

**Mix&Match**

```shell
# Basic network inspection
hednsextractor <target> | httpx -title -tech-detect -status-code

# Find all machines in Network and evaluate tech and status code (Very long and resource intensive)
nslookup <domain[.]tld> | awk 'Address: /{print$2}' | hednsextractor -silent -only-domains | httpx -silent -title -tech-detect -status-code

# grep "index of /"
nslookup <domain[.]tld> | awk 'Address: /{print$2}' | hednsextractor -silent -only-domains | httpx -silent -title -tech-detect -status-code | grep -i "index of /"

#
httpx -favicon -u domain/favicon.ico
ZoomEye query inconhash:"..."
```

---


### httpx

```shell
echo domain | httpx -title -tech-detect -status-code
# Jarm
httpx -jarm -u domain

# favicon
httpx -favicon -u domain
httpx -favicon -u duckduckgo.com/favicon.ico
httpx -match-favicon ...
httpx -filter-favicon '' -mc 200
```

---


### katana

```shell
# Basic discoverying
katana -u https://www.megacorpone.com
# Add custom Header
katana -u https://tesla.com -H 'Cookie: usrsess=AmljNrESo'
# Proxy
katana -u https://tesla.com -H 'Cookie: usrsess=AmljNrESo' -proxy http://127.0.0.1:8080
```

---


### subfinder + cdncheck + dnsx

```shell
# Automatic enum
subfinder -d hackerone.com -o subs.txt
# Brutefroce from wordlist
dnsx -silent -d zonetransfer.me -w dns_worldlist.txt 
# Bruteforce targeted subdomain using single or multiple keyword input, as d or w flag supports file or comma separated keyword inputs:
dnsx -silent -d domains.txt -w jira,grafana,jenkins

# This other command will find ONLY live hostnames due to the pipe to dnsx
subfinder -silent -d hackerone.com | dnsx -silent > active.txt
# The differce for exapmle in this situation is 24 subs for firsr command and 16 for second command
# To spot the inactive ones, to find the lines that exist only in one file coampred to another do:
# this find lines only existing in subs (the analyzed file compared to the other is always the second arg)
grep -Fxvf active.txt subs.txt > only-in-subs

# httpx
cat subs.txt | httpx -title -tech-detect -status-code

# inspect CDN
cat subs.txt | cdncheck -resp
# dnsx to inspect ASN and CDN
dnsx -l subs.txt -resp -cdn -asn

# dnsx to query records from those domains
dnsx -l subs.txt -resp -a -aaaa -cname -mx -ns -soa -txt

# A record for all subs
subfinder -silent -d hackerone.com | dnsx -silent -a -resp
# Get only IPs for that list
subfinder -silent -d hackerone.com | dnsx -silent -a -resp-only
subfinder -silent -d hackerone.com | dnsx -silent -resp-only

# Subdomains mapped across each ASN Zone and provider (issues with FQDN - solve it)
subfinder -silent -d zonetransfer.me | dnsx -silent -a -resp-only | asnmap -json -silent | jq -n '.TARGET |= [inputs]' > target.json
#
subfinder -silent -d zonetransfer.me | dnsx -silent -a -resp -json | jq 'with_entries(select(.key | in({"host":1, "a":1})))' | jq -n '[inputs]' > hostsfile.json
#
python asnrecon.py target.json hostsfile.json
#
# Old method
cat quarde.txt | sed 's/[][]//g' > noq.txt
sed -e "s/ /,/g" < noq.txt
#https://csvjson.com/csv2json
# hostname file


########
#####
subfinder -d targetdomain.com -silent | httpx | nuclei -t technologies/tech-detect.yaml
#
subfinder -d company.com | dnsx -resp-only | uncover

# Extract subdomains from given network range using PTR query:
echo 173.0.84.0/24 | dnsx -silent -resp-only -ptr
# Extract subdomains from given ASN using PTR query:
echo AS17012 | dnsx -silent -resp-only -ptr

# TLD bruteforce also available
dnsx -d google.FUZZ -w tld.txt -resp

# Wildcard filtering 
# To avoid huge amount of results to overflow. The way dnsx handles this is by keeping track of how many subdomains point to an IP and if the count of the subdomains increase beyond a certain threshold, it will check for wildcards on all the levels of the hosts for that IP iteratively:
dnsx -l subdomain_list.txt -wd airbnb.com -o output.txt
```

---

### naabu

```shell
#
naabu -host hackerone.com
#
naabu -p 80,443,21-23,u:53 -host hackerone.com
#
naabu -p - -exclude-ports 80,443
#
naabu -list hosts.txt

# IP address available for given ASN and runs the enumeration on them
echo AS14421 | naabu -p 80,443

# output in json format using -json switch
naabu -host 104.16.99.52 -json

# ports discovered can be piped to other tools
echo hackerone.com | naabu -silent | httpx -silent

#  IPv4 and IPv6
echo hackerone.com | dnsx -resp-only -a -aaaa -silent | naabu -p 80 -silent

# -ip-version 6 makes the tool use IPv6 addresses while resolving domain names
echo hackerone.com | naabu -p 80 -ip-version 6

# scan all the IPs of both version, ip-version 4,6 can be used along with -scan-all-ips flag
echo hackerone.com | ./naabu -iv 4,6 -sa -p 80 -silent

# nmap support for service discovery or any additional scans supported by nmap on the found results by Naabu
echo hackerone.com | naabu -nmap-cli 'nmap -sV -oX nmap-output'
```


### HEDnsExtractor

Find machines in the same Network (IP range):

```shell
#
hednsextractor -silent -target IP

# use 'grep' to match for a specific domain name - in ex. multiple scam sites with similar names
hednsextractor -silent -target IP | grep ...

# usage of findstr
hednsextractor -silent -target IP | findstr -l <string_to_match>

hednsextractor -silent -target IP | httpx -path /login -mc 200 -silent

hednsextractor -silent -target IP | httpx -path /secret/djvbvrzpj.js -mc 200 -silent

hednsextractor -silent -target IP | httpx -silent -title -tech-detect -status-code -random-agent

hednsextractor -silent -target IP | httpx -silent -title -tech-detect -status-code -random-agent -location
```

**Workflows**

```shell
hednsextractor -workflow WellsFargo_Detection.yaml

# content of WellsFargo_Detection.yaml
domains:
  - 104.237.252.65
  - cancelfrgoref3eb0d.com
  
regex: (well|frgo|fargo)
### EOF
```

Example 1: regex: `(well|frgo|fargo)`
Example 2: regex: `(*gov\d+)`
Example 3: regex: `(cancel\d{3})`




---

### Uncover

Finds exposed hosts on the internet so the field to query has to be something that would also be accepted in input from those search engines

```shell
# Defaul query API is shodan

# Single query against multiple search engine
echo jira | uncover -e shodan,censys,fofa,quake,hunter,zoomeye,netlas,criminalip

# Multiple query against multiple search engine
uncover -shodan 'http.component:"Atlassian Jira"' -censys 'services.software.product=`Jira`' -fofa 'app="ATLASSIAN-JIRA"' -quake 'Jira' -hunter 'Jira' -zoomeye 'app:"Atlassian JIRA"' -netlas 'jira' -criminalip 'Jira'

# -f, -field flag can be used to indicate which fields to return, currently, ip, port, and host are supported and can be used to return desired fields.
uncover -q jira -f host -silent

# Field Formatting
echo kubernetes | uncover -f https://ip:port/version -silent

# Output of uncover can be further piped to other projects in workflow accepting stdin as input, for example:
# Runs naabu for port scanning on the found host
uncover -q example -f ip | naabu
# Runs httpx for web server probing the found result
uncover -q title:GitLab | httpx
# Runs httpx on host/ports obtained from shodan-internetdb
uncover -q 51.83.59.99/24 | httpx

# Vuln assesment
uncover -q 'org:"Example  Inc."' | httpx | nuclei

#
subfinder -d company.com | dnsx -resp-only | uncover

#  Shodan InternetDB, passive port scanning is now a real thing.
echo "51.83.59.99/24" | uncover

# companies often use uniform SSL certificates with identifying properties such as common names, you can sometimes identify assets that have been forgotten about or don’t have an active DNS record.
uncover -q 'ssl:"Uber Technologies, Inc."' | httpx -silent
```

---

### tlsx

TLS based data collection and analysis

```shell
AS1449 # ASN input
173.0.84.0/24 # CIDR input
93.184.216.34 # IP input
example.com # DNS input
example.com:443 # DNS input with port
https://example.com:443 # URL input port

# comma-separated host input:
tlsx -u 93.184.216.34,example.com,example.com:443,https://example.com:443 -silent
# file based host input:
tlsx -list host_list.txt

# port input
tlsx -u hackerone.com -p 443,8443
tlsx -u hackerone.com -p port_list.txt

# tool against the given CIDR range and returns hosts that accepts tls connection on port 443.
echo 173.0.84.0/24 | tlsx

# TLS certificate contains DNS names under subject alternative name and common name field that can be extracted using -san, -cn flag
echo 173.0.84.0/24 | tlsx -san -cn -silent
# optionally -resp-only flag can be used to list only dns names in CLI output.
echo 173.0.84.0/24 | tlsx -san -cn -silent -resp-only

# piping tls subdomains to dnsx to filter passive subdomains and passing to httpx to list hosts running active web services
echo 173.0.84.0/24 | tlsx -san -cn -silent -resp-only | dnsx -silent | httpx

# TLS / Cipher Probe
subfinder -d hackerone.com | tlsx -tls-version -cipher

# Expired / Self Signed / Mismatched / Revoked / Untrusted Certificate
tlsx -l hosts.txt -expired -self-signed -mismatched -revoked -untrusted

# JARM TLS Fingerprint
echo hackerone.com | tlsx -jarm -silent

# JA3 TLS Fingerprint
echo hackerone.com | tlsx -ja3 -silent

# JSON format, for automation and post processing using -json output is most convenient option to use.
echo example.com | tlsx -json -silent | jq .
# Very useful to grab all SAN for which a cert is valid for and investigate further:
echo zonetransfer.me | tlsx -json -silent | jq -r '.subject_an | .[]' > san-domains.txt
```

Missing part on scannig mode options:

tlsx provides multiple modes to make TLS Connection -

* auto (automatic fallback to other modes upon failure) - default
* ctls (crypto/tls)
* ztls (zcrypto/tls)
* openssl (openssl)

Handsahke early termiantio [read](https://github.com/erbbysam/Hunting-Certificates-And-Servers/blob/master/Hunting%20Certificates%20%26%20Servers.pdf) Pre-Handshake (Early Termination) tlsx supports terminating SSL connection early which leads to faster scanning and less connection request (disconnecting after TLS serverhello and certificate data is gathered).

`tlsx -u example.com -pre-handshake `

pre-handshake mode utilizes ztls (zcrypto/tls) which also means the support is limited till TLS v1.2 as TLS v1.3 is not supported by ztls library.

Minimum and Maximum TLS versions can be specified using -min-version and -max-version flags, as default these value are set by underlying used library.

The acceptable values for TLS version is specified below.

- ssl30
- tls10
- tls11
- tls12
- tls13


---

### asnmap

```shell
# asnmap by default returns the CIDR range for given input.
echo GOOGLE | asnmap

#
asnmap -a AS45596 -silent
asnmap -i 100.19.12.21 -silent
asnmap -d hackerone.com -silent
asnmap -org GOOGLE -silent

#
echo GOOGLE | asnmap -silent

# JSON format, for automation and post processing using -json
echo hackerone.com | asnmap -json -silent | jq
# Retrieve only ASN CIDR range IPs
echo hackerone.com | asnmap -json -silent | jq -r '.as_range | .[]'

# CSV
echo hackerone.com | asnmap -csv -silent

# Piping
echo AS54115 | asnmap | tlsx
echo AS54115 | asnmap | dnsx -ptr
echo AS54115 | asnmap | naabu -p 443
echo AS54115 | asnmap | naabu -p 443 | httpx
echo AS54115 | asnmap | naabu -p 443 | httpx | nuclei -id tech-detect
```


---


### gau 

```shell
# basic search
gau <domain[.]tld> --subs

#
gau <domain[.]tld> --subs | cut -d"?" -f1 | grep -E "\.js+(?:on|)$" | tee urls.txt
ffuf -w urls.txt:HFUZZ -u HFUZZ -replay-proxy http://local-proxy:port
# Suggested Burp or proxify

# SSRF Mining
gau <domain[.]tld> --subs | ... ssrf | sort -u | httpx -mc 200 | ... "burpcollaborator" >> ssrfuzzdomain.txt; ffuf -c -w ssrfuzzdomain.txt -u FUZZ

# Redirectors parameters Mining
sudo gau <domain[.]tld> | sudo httpx -silent -timeout 2 -threads 100 | grep -E "redirect|url|target|returnUri|next|rurl|dest|destination|redir|redirect_uri|redirect_url|image_url|return|returnTo|return_to|continue|return_path|next_url|checkout_url|retURL|link|file|fallback|callback_url"
```

---


### Nuclei

```shell
#
nuclei -u https://example.com

# Custom template directory or multiple template directory can be executed as follows:
nuclei -u https://example.com -t cves/ -t exposures/

# Templates can be executed against a list of URLs:
nuclei -list http_urls.txt

# run all the templates installed at ~/nuclei-templates/ directory and has cve tags in it:
nuclei -u https://example.com -tags cve

# use only templates that have been tagged with the specified value. 
nuclei -u https://jira.targetdomain.site -tags jira,generic

# run all the templates available under ~/nuclei-templates/exposures/ directory and has config tag in it:
nuclei -u https://example.com -tags config -t exposures/

# runs all templates with cve tags AND has critical OR high severity AND geeknik as author of template:
nuclei -u https://example.com -tags cve -severity critical,high -author geeknik

# Multiple filters can also be combined using the template condition flag (-tc) that allows complex expressions like the following ones:
nuclei -tc "contains(id,'xss') || contains(tags,'xss')"
nuclei -tc "contains(tags,'cve') && contains(tags,'ssrf')"
nuclei -tc "contains(name, 'Local File Inclusion')"

#
nuclei -update-templates

#
nuclei -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) / nuclei' -list urls.txt -tags cves
#
nuclei -list urls.txt -t cves/ -exclude-templates cves/2020/CVE-2020-XXXX.yaml
# Example of multiple template exclusion
nuclei -list urls.txt -exclude-templates exposed-panels/ -exclude-templates technologies/
# Example of excluding templates with single tag
nuclei -l urls.txt -t cves/ -etags xss
nuclei -l urls.txt -t files/exposed-svn.yaml
# Example of excluding templates with multiple tags
nuclei -l urls.txt -t cves/ -etags sqli,rce
```

```shell
#
subfinder -d targetdomain.com -silent | httpx | nuclei -t technologies/tech-detect.yaml

# Automatic Selection (-as) attempt to fingerprint the technology stack and components used on the target, then select templates that have been tagged with those tech stack keywords. Example:
nuclei -u https:// my.target.site -as

# Only New Templates (-nt) This option will use only templates that were added from the last update (for example by running nuclei -update-templates). Example:
nuclei -u https://my.target.site -nt

# Only specific templates:
nuclei -u https://my.target.site -t file/logs/python-app-sql-exceptions.yaml -t exposures/files/pyproject-disclosure.yaml

# Rate limiting
# restrict outgoing requests to 3 per second and only 2 concurrent templates):
nuclei -u https://my.target.site/ -rl 3 -c 2

# Resuming Scans
nuclei -l targets-file.txt -resume /path/to/resume-file.cfg

# Client Cert Auth
# scanned hosts may require a client certificate for authentication.
nuclei -u https://api.target.site -cc /path/to/client-cert.pem
# Other options that relate to client certificate authentication are the -ck and -ca switches that allow you to provide PEM-encoded private key and Certificate Authority (CA) files to be used in authentication to hosts.
```

Using Nuclei with **Uncover**

```shell
export SHODAN_API_KEY=xxx
export CENSYS_API_ID=xxx
export CENSYS_API_SECRET=xxx
export FOFA_EMAIL=xxx
export FOFA_KEY=xxx
export QUAKE_TOKEN=xxx
export HUNTER_API_KEY=xxx
export ZOOMEYE_API_KEY=xxx

# 
nuclei -h uncover

UNCOVER:
   -uc, -uncover                  enable uncover engine
   -uq, -uncover-query string[]   uncover search query
   -ue, -uncover-engine string[]  uncover search engine (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas,criminalip) (default shodan)
   -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")
   -ul, -uncover-limit int        uncover results to return (default 100)
   -ucd, -uncover-delay int       delay between uncover query requests in seconds (0 to disable) (default 1)

#
nuclei -id 'CVE-2021-26855' -uq 'vuln:CVE-2021-26855' -ue shodan

# It can also read queries from templates metadata and execute template against hosts returned by uncover for that query.
# Example of template execution using template-defined search queries.
# Template snippet of CVE-2021-26855
##########
metadata:
  shodan-query: 'vuln:CVE-2021-26855'
##########

nuclei -t cves/2021/CVE-2021-26855.yaml -uncover
nuclei -tags cve -uncover

# Reporting
nuclei -l urls.txt -t cves/ -rc issue-tracker.yaml
nuclei -l urls.txt -t cves/ -irr -markdown-export reports

# Here is an example to query metrics while running nuclei as following:
nuclei -t cves/ -l urls.txt -metrics
curl -s localhost:9092/metrics | jq .
```

* host-spray : All templates are iterated over each target.
* template-spray : Each template is iterated over all targets.
* auto(Default) : Placeholder of template-spray for now.

---

### Shodan

```shell
shodan domain -D <domain[.]tld> -S
# unzip it
gzip -d *.gz

# Using 'jq' to parse it
# parse each entry
jq -cs '.[0]' domain.com.json
jq -cs '.[1]' domain.com.json
jq -cs '.[2]' domain.com.json

# parse the hosts file
jq -cs '.[0]' domain.com.json
#
jq -cs '.[0]' domain.com-hosts.json | jq -r
#
jq -r '.domains' domain.com-hosts.json
#
jq -r '.hostnames' domain.com-hosts.json
#
jq -r '.ip_str' domain.com.json

# Chain output
jq -r '.ip_str' domain.com.json | httpx -titles -port 80,443,8080,8000 | nuclei
```

**Misc search**

```shell
# Search by Organization Name and multiple parameters
shodan search org:\"Organization Name\" --fields ip_str,ports,http.title 

# exclude ports 80 and 443
shodan search org:\"Organization Name\" \!port:80,443 --fields ip_str,ports,http.title

#
shodan search org:\"Organization Name\" \!port:80,443 --fields ip_str,ports,http.title | awk '{print $1,$2}' | tr " " ":"
#
shodan search org:\"Organization Name\" \!port:80,443 --fields ip_str,ports,http.title | awk '{print $1,$2}' | tr " " ":" | httpx -title -follow-host-redirects

#
shodan search ssl:domain.com --fields ip_str,port | awk '{print $1,$2}' | tr " " ":"
#
shodan search ssl:domain.com \!port:443 --fields ip_str,port | awk '{print $1,$2}' | tr " " ":" | httpx -title -tech-detect -status-code

# Search by ASN
shodan search asn:<...> --fields hostnames | tr ";" "\n" | sort -u | domainparser | sort -u
#
shodan search asn:<...> --fields hostnames | tr ";" "\n" | sort -u | domainparser | sort -u | xargs -I{} shodan search ssl:{} --fields ip_str,port

shodan search org:\"Organization Name\" http.favicon.hash: --fields ip_str,port --separator " "
```

**Shodan and Nuclei**

```shell
# Spring Boot nuclei search
shodan search org:"Org name" http.favicon.hash:116323821 --fields ip_str,port --separator  " " | awk '{print $1,$2}' | httprobe | nuclei -t workflow/springboot-pwner-workflow.yaml

# F5 BIG IP pwner
shodan search org:"Org name" http.favicon.hash:-335242539 --fields ip_str,port --separator  " " | awk '{print $1,$2}' | httprobe | nuclei -t workflow/bigip-pwner-workflow.yaml
```

---

### shodan InternetDB

```shell
#
curl https://internetdb.shodan.io/IP
#
curl -X 'GET' 'https://internetdb.shodan.io/IP' -H 'accept: application/json' | jq


# Domain + IP
curl -X 'GET' 'https://internetdb.shodan.io/IP' -H 'accept: application/json' | jq -r '.hostnames | .[]' | dnsx -silent -resp -a

# Domain + ASN + IP
curl -X 'GET' 'https://internetdb.shodan.io/IP' -H 'accept: application/json' | jq -r '.hostnames | .[]' | dnsx -silent -resp -asn

# 
```