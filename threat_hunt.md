# Threat Hungtig Techniques

<!-- TOC section dont edit -->

**Table of Contents**

1. [Search Engines](#search-engines)  
	1.2 [FOFA](#fofa) 
	1.3 [Censys](#censys) 
	1.4 [Shodan](#shodan) 
	1.5 [ZoomEye](#zoomeye)
2. [Retrieve Info](#retrieve-info)  
	2.1 [](#)
3. [CTI Platforms](#cti-platforms)
    3.1 [VirusTotal](#virustotal)
    3.2 [ThreatBook](#threatbook)
4. [](#)

<!-- TOC section dont edit -->

## Search Engines

List of most useful tools to perform information gathering about assets, infrastructures and so on.

Collection of methods to hunt down spefic assets, the procedures and infos about why a particular content is relevant will be described later on in the documet, here we only collect all the commands to use in order to use that particular SE.

---

### FOFA

* **GitHub FOFA** [FofaInfo](https://github.com/FofaInfo/Awesome-FOFA)
* **Unofficial CLI** [fofax](https://github.com/xiecat/fofax)
* **New Official GO CLI** [GoFOFA](https://github.com/FofaInfo/GoFOFA)

```bash
# host
host="test.domain.com"

## Fuzzy host search
# subdomains containing the keyword "test", where the "test" keyword suffix may have other character
host*="test*.domain.com"

# subdomains containing the keyword "test" where the "test" keyword may have other characters before or after it
host*="*test*.domain.com"


# assets with the main domain domain.com but with subdomains containing the keyword "test" followed by exactly one additional character
host*="test?.domain.com"

# subdomains with exactly five characters following the keyword "test"
host*="?????.domain.com"
# not sure if the first is a docs error
host*="?????test.domain.com"

# multiple fuzzy searches by combining the search statements
host*="test*.baidu.com.*"

# search for all domains containing the keyword "test" regardless of their position in the domain name, we can use the following
host*="*test*"

#-------------------------------------------------------------------------------------

## Fuzzy service Banner search
banner="mysql version"

# all versions matching the pattern 5.?.*
banner="mysql version" && banner*="5.?.*"

# specific version
banner="mysql version" && banner*="5.5.4*"

#-------------------------------------------------------------------------------------

# Misc Fuzzy

## Protocols Fuzzy search
protocol*="snmp*"

# hint on cloud service providers
cloud_name*="Cloud*"

# assets with a four-digit port using fuzzy search for a known search result
domain="fofa.info" && port*="????"



#-------------------------------------------------------------------------------------

## Misc C2 premade queries
# cobalt
protocol=="cobaltstrike"
cert="Major Cobalt Strike"
cert="Major Cobalt Strike" && after="2020-01-01"
cert="SHA256 fingerprint" && after="2020-01-01"

#-------------------------------------------------------------------------------------

title="VNC- Login" && icon_hash="<value>"

org="<value>" && header="<value>" && header="<value>" && domain!=""

icon_hash="<value>" && domain!=""
```


#### Exposure management

When conducting attack surface review, the core requirement is to be as comprehensive and accurate as possible. One effective method is to use the `cert.is_valid` syntax to perform combined queries and quickly verify if an asset's certificate is issued by a trusted certificate authority. For example, using the syntax `cert="fofa.info" && cert.is_valid=true`.

`cert.is_valid` is used to determine the validity of a certificate. However, during the process of reviewing the attack surface, we often encounter distractions. Many assets are not part of the organization's assets but are intentionally associated with the DNS records of major companies. For example, after a DDoS attack, some websites deliberately bind their DNS to "baidu.com" to redirect the attack traffic to a large internet company

`ip="" && cert.is_match=false && is_domain=true`: we find that those domain names intentionally bound to the IP addresses of large companies are not the valid attack surface we need to consider.

The most straightforward approach is to simulate the behavior of a browser and check if the domain name matches the information in the certificate. However, this approach immediately raises another question: If a certificate is valid but does not match the domain name, should we consider the asset as part of the target exposure or as interference data?

Let's summarize the previously used syntax and the two new additions:

`cert.is_valid`: Evaluates the trustworthiness of the certificate (true for trusted, false for untrusted or self-signed)
`cert.is_match`: Checks if the certificate matches the domain name of the asset (true for a match, false for a mismatch)
`cert.is_expired`: Determines if the certificate has expired (true for expired, false for not expired)

Returning to the example mentioned earlier, using the syntax `cert="fofa.info" && cert.is_valid=true && cert.is_match=true` allows us to exclude distracting assets.

Furthermore, in cases where the trustworthiness is true but the match is false, indicating that the asset still belongs to itself, as mentioned in the previous text, we can directly retrieve it using the syntax `cert="abchina.com.cn" && cert.is_valid=true && cert.is_match=false`.

Full article can be found [here](https://github.com/FofaInfo/Awesome-FOFA/blob/main/Basic%20scenario/How%20to%20effectively%20eliminate%20interference%20through%20certificates%20in%20the%20asset%20discovery.md)



#### Advanced Use Cases

**Asset expansion**

##### Unmasking Silver Fox APT

```bash
# first look for IP
ip=""

# identified a new domain that has the same IP


# Using the SDK feature of asset association for query.
# SDK hash is used to identify web components or technologies by that hash
# It detects specific sdk kits or software package or framework
sdk_hash="5IcXyBJ8QrxlDLQFTl2DCHG0Z42JHfk6"

# title jumping
## upon discovering somthing new about an asset new info could lead to new titles that can lead to similar assets. So the concept is to always perform title search based on new discoveries and cross-reference each time with what you think may be relevant in relation to the main asset lookup

# Upon looking in the website body of every suspiciouis domain, a pattern inside the static/js/ folder is recognized and a particualar file that has a code that trigger a download is matched in all of this domains, also confirmed by the js_md5 hash of that file file equal in each domain

# we can continue to use the following search syntax to conduct in-depth queries, and this query result hits 28 data and 7 independent IP addresses.

js_name="static/js/quanzhan.js" && body="downapp"

js_md5="a13f7f208ba534681deadb1ec7a2e54a" && body="downapp" && (body="count" || body="fileUrl")

host*="*.lianhuawangluo??.xyz" || host*="*.hehuashangwu??.xyz"

# dirty raw searches of text, names and ext inside websites body
body="function downapp" && (body="count" || body="fileUrl") && (body="exe" || body="msi" || body="zip")

## Next findings
# new site, and directly look for FID references
fid=""
```

##### Tracking Bitter APT

```bash
host=""

# After having more than two IOC information, the next step is to extract the common features of multiple IOC. The overall idea of this step is to compare the common parts of the two IOC, such as title, body, cert, etc.

# public information shows that the main attack method of this Team is to send OFFICE document classes through phishing, so the domain names extracted from IOC are actually the carriers of Trojans. It is found through analysis that the download link features of the Trojan are all: Domain/Random second-level directory/Random name PHP file? Parameter=username*computername

#1. The title feature of the homepage is title="403 Forbidden"
#2. Server header information: server="LiteSpeed"
#3. Response header size: header="Content-Length: 1229"
#4. Alternative service header: header='"Alt-Svc: h3=:443"'

# range of these general features is too large

# Through comparative analysis, more clues are found:
#1. Their service behavior features will definitely open 80,443 (SSL)
#2. The domain name will definitely set CNAME
#3. The certificate belongs to the free certificate, and the certificate must be a valid certificate without expiration
#4. And the certificate subject will definitely bind a domain name
#5. The website does not have a Favicon icon

header='Alt-Svc: h3=":443"' && title="403 Forbidden" && header="Content-Length: 1229" && port="443" && server="LiteSpeed" && cert.issuer.cn="R3"

#1. domain!="" (domain name is not empty)
#2. cert.is_valid=true (certificate is trustworthy)
#3. cert.is_expired=false (certificate has not expired)
#4. icon_hash="" (Favicon chart is empty)
#5. cert.subject.cn*="*.*" (the certificate holder will definitely bind the domain name)
#6. cname!="" (CName is not empty)

header='Alt-Svc: h3=":443"' && title="403 Forbidden" && header="Content-Length: 1229" && port="443" && server="LiteSpeed" && cert.issuer.cn="R3" && domain!="" && cert.is_valid=true && cert.is_expired=false && icon_hash="" && cert.subject.cn*="*.*" && cname!="" && after="2023-08-01"

#To be on the safe side, we need to verify the correctness of the extracted features above to confirm whether it is a containment relationship with the sample.
#So add host="<initial_host_value>"

header='Alt-Svc: h3=":443"' && title="403 Forbidden" && header="Content-Length: 1229" && port="443" && server="LiteSpeed" && cert.issuer.cn="R3" && domain!="" && cert.is_valid=true && cert.is_expired=false && icon_hash="" && cert.subject.cn*="*.*" && cname!="" && after="2023-08-01" && host="<initial_host_value>"

# perform statistical analysis on the (Org) information of the existing samples. Here we can see that this Team will purchase web services for placement at several fixed service providers.

header='Alt-Svc: h3=":443"' && title="403 Forbidden" && header="Content-Length: 1229" && port="443" && server="LiteSpeed" && cert.issuer.cn="R3" && domain!="" && cert.is_valid=true && cert.is_expired=false && icon_hash="" && cert.subject.cn*="*.*" && cname!="" && (org="ARTERIA Networks Corporation" || org="Advania Island ehf" || org="HOSTWINDS" || org="Host Sailor Ltd" || org="Akamai Connected Cloud" || org="NAMECHEAP-NET" || org="Iws Networks LLC" || org="Verdina Ltd." || org="AMAZON-02" || org="Melbikomas UAB" || org="GROUP-IID-01" || org="GLOBALCOMPASS" || org="Contabo GmbH" || org="INCAPSULA" || org="Neerja Softwares Pvt Ltd" || org="Commission on Science and Technology for" || org="Belcloud LTD" || org="DIGITALOCEAN-ASN" || org="QUICKPACKET")

# Randomly query from the results here to the threat intelligence platform, just take the first one to try, you can see that some domain names have been marked as the tags of the Bitter Team (APT Bitter) or malicious tags.

# Then the last step, we perform collision matching through the URL PATH collected from the public samples. Sample retrieved from "maltrail"

fofax -q ' header="Alt-Svc" && title="403 Forbidden" && header="Content-Length: 1229" && port="443" && cert.is_valid=true && cert.is_expired=false && icon_hash="" && cert.subject.cn*="*.*" && server="LiteSpeed" && cert.issuer.cn="R3" && cname!="" && domain!="" && (org="ARTERIA Networks Corporation" || org="Advania Island ehf" || org="HOSTWINDS" || org="Host Sailor Ltd" || org="Akamai Connected Cloud" || org="NAMECHEAP-NET" || org="Iws Networks LLC" || org="Verdina Ltd." || org="AMAZON-02" || org="Melbikomas UAB" || org="GROUP-IID-01" || org="GLOBALCOMPASS" || org="Contabo GmbH" || org="INCAPSULA" || org="Neerja Softwares Pvt Ltd" || org="Commission on Science and Technology for" || org="Belcloud LTD" || org="DIGITALOCEAN-ASN" || org="QUICKPACKET")' -fs 1000 | httpx -mc 404 -path "/c4ca4238a0b923820dcc509a6f75849b" |seds/c4ca4238a0b923820dcc509a6f75849b//g | httpx -path apt_path.txt -sc -mc 200,403
```

[maltrail](https://github.com/stamparm/maltrail/tree/master/trails/static/malware)


##### Observer Stealer

```bash
#
banner="access-control-expose-headers: Content-Type, Authorization" && banner="404 Not Found" && banner="Content-Length: 40"
```

##### Sidewinder APT

```bash
#################
# Asset Expansion
#################
# searches about three malicious domains
domain="<IOCs_domain>"

# they got all three the same jarm3 fingerprint
# so look for jarm
jarm="<jarm>"
# too many resutls. needed to narrow it down even further
# the three domains shared some common headers in the response page, so add them to the query
jarm="<jarm>" && header="HTTP/1.1 404 Not Found" && header="Server: nginx" && header="Content-Type: text/html"
# still a too large pool so include also the 'Content-Length' because two shared the same and the third was rather unique
jarm="<jarm>" && header="HTTP/1.1 404 Not Found" && header="Server: nginx" && header="Content-Type: text/html" && (header="Content-Length: 183" || header="Content-Length: 535")

# smaller assets pool but need verification to continue on that way, so inserting the initial domain names in the query should be a possible verification
jarm="<jarm>" && header="HTTP/1.1 404 Not Found" && header="Server: nginx" && header="Content-Type: text/html" && (header="Content-Length: 183" || header="Content-Length: 535") && (domain="<IOCs_domain1>" || domain="<IOCs_domain2>")

## .1
# This confirm that the final asset expansion query is acutally the previous one without the domains.
jarm="<jarm>" && header="HTTP/1.1 404 Not Found" && header="Server: nginx" && header="Content-Type: text/html" && (header="Content-Length: 183" || header="Content-Length: 535")

# as mentioned the third domain has (anomaly) different headers: its features are basically similar to the features of the first two domain names, only Content-Length is 555, and Server is nginx/1.23.2.

## .2
header="HTTP/1.1 404 Not Found" && header="Server: nginx/1.23.2" && header="Content-Type: text/html" && header="Content-Length: 555" && jarm="<jarm>"

###### Next set of IOCs :
# different domains from the previous three mentioned
# their JARM fingerprints are the same (but different from the first three domains), and other features are consistent with the features of the above clues, only content-length is 228

## .3
jarm="<jarm>" && header="Content-Length: 228" && header="HTTP/1.1 404 Not Found" && header="Server: nginx"

# In this expansion, we have organized three asset rules for this according to the IOC.
## 1 - 2 - 3

####################
# Asset Verification
####################
# Cross references between multiple CTI platforms 
```


##### APT-C-23

Android malware cases. Here the initial asset expansion query is formulated by looking a the website body (in particular js code):

```bash
status_code="200" && body="name=\"keywords\"" && body="name=\"description\"" && body="rel=\"canonical\""  && (body="onclick=\"getApp()\"" || body="onclick=\"getAppVersionOne()\"")

status_code="200" && body="name=\"keywords\"" && body="name=\"description\"" && body="rel=\"canonical\"" && (body="onclick=\"getApp()\"" || body="onclick=\"getAppVersionOne()\"") && (body="src=\"js/myScript.js\"" || body="src=\"assets/js/myScript.js\"" || body="src=\"js/script.js\"")
```

Look at the article for further analysis because its involve reverse eng of the malicious apps


##### Ducktail

FOFA search for the domain is conducted to identify its features. Features extracted include its header response, icon status, certificate status, JARM value, hash value computed from the body, and more. After organizing these features, the following combination is obtained:


```bash
header="HTTP/1.1 404 Not Found" && header="Server: cloudflare" && icon_hash="" && header="Transfer-Encoding: chunked" && cert.issuer!="" && cert.subject.org="" && cert.issuer.cn!="" && cert.is_valid=true && jarm="<jarm>" && body_hash="-1840324437" && header!="X-Powered-By" && header!="Strict-Transport-Security" && header!="Pragma"

# Apart from the above feature extraction, it is observed that the data's ISP is Cloudflare, and there is no icon or title. As the header response format is consistent, the computed hash value is directly taken for combination:

org="CLOUDFLARENET" && icon_hash="" && title="" && header_hash="-2069571899"

### C2 IP

header="404 Not Found" && header="Transfer-Encoding: chunked" && header="Server: Microsoft-IIS" && icon_hash="" && title="" && header_hash="-324809210"

#

fofax -q 'header="404 Not Found" && header="Transfer-Encoding: chunked" && header="Server: Microsoft-IIS" && icon_hash="" && title="" && header_hash="-324809210"' -fs 10000 | httpx -path /api/check -sc -cl -mc 200 -ml 355

#

cat url.txt | httpx -sc -cl -path path.txt -mc 200

#Integrating the information extracted so far, we summarize that this criminal team has multiple IOC characteristics.
#1. Fixed file download paths:
#  /file/t/mainbot.exe
#  /file/t/RdpService.exe
#  /file/t/TermService.exe
#  /file/rdpwrap.txt
#2. Fixed authentication path with consistent response packet size
#  /api/check
#  (hxxp://138.201.8.186/api/check [200] [355])
#3. Domain addresses are routed through Cloudflare for traffic proxying, undergoing CDN relay.
```

Here extracting data from teh dropped files and analyzing the exes behaviour on vt sandbox, some aditional infos are obtained, like C2 address and some fixed path called by the dropper.
Further quering the newly discovered domains with this IOCs we manage to find other assets related to that group.


##### COLDRIVER

Starting point, IOCs obtained from google TAG analysis report, a path and a C2 domain.

```bash
## C2 address
# lead to an open port: 3000
# and a partiular hexadecimal banner value

# query to expand it:
banner="\x15\x03\x03\x00\x02\x022" && port="3000"

# cert info also are particular so was worth given a try add them to the query
banner="\x15\x03\x03\x00\x02\x022" && port="3000" && cert="Internet Widgits Pty Ltd"

# crucial clue, which is the certificate expiration date. We searched through the certificate expiration date and the default organization name:
cert="Internet Widgits Pty Ltd" && cert="2023-06-23 15:59 UTC"

banner="\x15\x03\x03\x00\x02\x022" && port="3000" && cert="Internet Widgits Pty Ltd" && cert="2023-06-23 15:59 UTC"

```


---

### Censys

Each single query may be chained with others using logical operators in order to get narrowed results

```bash
# IP
ip:"<ip>"

# SSL - Certs searches
## leaf_data: it's specific to the end-entity (leaf) certificate only, aka final server or domain. Cert that the server present during TLS hand shake. (non including certs of intermediate or root authorities)
## chain: data about the entire chain that is presented by the server during the TLS hand shake. So it's leaf cert + intermediate certs + root certs data. Useful to validate entire cert chain

## We usually search both (with same Hash values) when the certificate in question is self-signed, so there is a Single Cerificate in the chain (no intermedaite certs). So the server might present a single cert which is both the leaf and effectively the entire chain.

services.tls.certificates.leaf_data.fingerprint: <SHA256 fingerprint> or services.tls.certificates.chain.fingerprint: <SHA256 fingerprint>

same_service(services.tls.certificates.leaf_data.fingerprint:"<SHA256 fingerprint>" and not services.port:"60000")

same_service(services.tls.certificates.leaf_data.fingerprint:"<SHA256 fingerprint>" and not labels:c2)

services.http.response.favicons.hashes="sha256:<hash_here>" and not services.tls.certificates.leaf_data.fingerprint: <SHA256 fingerprintr>

same_service(services.http.response.favicons.hashes="sha256:<hash_here>" or services.tls.certificates.leaf_data.fingerprint: <SHA256 fingerprint>) and services.software.product="Asset Reconnaissance Lighthouse (ARL)"

same_service((services.http.response.html_title="VIPER" and services.http.response.body_size:{691,692}) or (services.http.response.favicons.hashes="sha256:<hash_here>" or services.tls.certificates.leaf_data.fingerprint: <SHA256 fingerprint>))

443.https.tls.certificate.parsed.fingerprint_sha256:<SHA256 fingerprint>

#-------------------------------------------------------------------------------------
# FAV ico
services.http.response.favicons.hashes="sha256:<hash_here>"
services.http.response.favicons.hashes="mmh3:<hash_here>"

#-------------------------------------------------------------------------------------

# Body
same_service(services.http.response.html_title="VIPER" and services.http.response.body_size:"692")

#-------------------------------------------------------------------------------------

# SSH Fingerprint
services.ssh.server_host_key.fingerprint_sha256: <fingerprint>

#-------------------------------------------------------------------------------------


# Cobalt default
services.certificate: {
    "64257fc0fac31c01a5ccd816c73ea86e639260da1604d04db869bb603c2886e6",
    "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c"
}
or services.tls.certificates.leaf_data.issuer.common_name: "Major Cobalt Strike"
or services.tls.certificates.leaf_data.subject.common_name: "Major Cobalt Strike"

# Metasploit default
services.http.response.html_title: "Metasploit" and (
    services.tls.certificates.leaf_data.subject.organization: "Rapid7"
    or services.tls.certificates.leaf_data.subject.common_name: "MetasploitSelfSignedCA"
)
or services.jarm.fingerprint: {
    "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d",
    "07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823"
}

#-------------------------------------------------------------------------------------

# Nessus Scanner Servers
services.http.response.headers.server: "NessusWWW"
or services.tls.certificates.leaf_data.subject.organizational_unit: "Nessus Server"

#-------------------------------------------------------------------------------------

# NTOP Network Analyzers
services.http.response.html_title: "Welcome to ntopng"
or same_service(
    services.http.response.html_title: "Global Traffic Statistics"
    and services.http.response.headers.server: "ntop/*"
)

#-------------------------------------------------------------------------------------

# Merlin C2

services.jarm.fingerprint: "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38"

#-------------------------------------------------------------------------------------

# Mythic C2
same_service(port: 7443 and tls.certificates.leaf_data.subject.organization: "Mythic")


#-------------------------------------------------------------------------------------

# Covenant C2

same_service(
    http.response.body: {"Blazor", "covenant.css"}
    and tls.certificates.leaf_data.issuer.common_name: "Covenant"
)

#-------------------------------------------------------------------------------------

# PoshC2
same_service(
    services.tls.certificates.leaf_data.subject.common_name="P18055077" and
    services.tls.certificates.leaf_data.subject.province="Minnesota" and
    services.tls.certificates.leaf_data.subject.locality="Minnetonka" and
    services.tls.certificates.leaf_data.subject.organization="Pajfds" and
    services.tls.certificates.leaf_data.subject.organizational_unit="Jethpro"
)

#-------------------------------------------------------------------------------------

# Sliver C2
same_service(
    services.tls.certificates.leaf_data.pubkey_bit_size: 2048 and
    services.tls.certificates.leaf_data.subject.organization: /(ACME|Partners|Tech|Cloud|Synergy|Test|Debug)? ?(co|llc|inc|corp|ltd)?/ and
    services.jarm.fingerprint: 3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910 and
    services.tls.certificates.leaf_data.subject.country: US and
    services.tls.certificates.leaf_data.subject.postal_code: /<1001-9999>/
)

#Note: This search uses regex and requires a paid account.
#Pro-Tip: Try removing JARM to find even more Sliver instances.

#-------------------------------------------------------------------------------------

# Brute Ratel C4
services.http.response.body_hash="sha1:1a279f5df4103743b823ec2a6a08436fdf63fe30"

#-------------------------------------------------------------------------------------

# Empire C2
same_service(
    services.http.response.body_hash: {"sha1:bc517bf173440dad15b99a051389fadc366d5df2", "sha1:dcb32e6256459d3660fdc90e4c79e95a921841cc"}
    and services.http.response.headers.expires: 0
    and services.http.response.headers.cache_control: "*"
)

#-------------------------------------------------------------------------------------

## Service Banner
# Responder Server

services.banner="HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-IIS/7.5\r\nDate:  <REDACTED>\r\nContent-Type: text/html\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n"

## Service Banner Hash
# Raccoon Stealer V2 (RecordBreaker C2)

services.banner_hashes: "sha256:7987d0c39c4839572ab88c6d82da01395f74e0c31f12d94c58d0e1bed0b0c75c"

#-------------------------------------------------------------------------------------

# NimPlant C2
services.http.response.headers.Server: "NimPlant C2 Server" or services.http.response.body_hashes: "sha256:636d68bd1bc19d763de95d0a6406f4f77953f9973389857353ac445e2b6fff87"

#-------------------------------------------------------------------------------------

# RedGuard
services.tls.certificates.leaf_data.subject_dn: "C=CN, L=HangZhou, O=Alibaba (China) Technology Co.\\, Ltd., CN=\*.aliyun.com"

#-------------------------------------------------------------------------------------

# AsyncRAT
services.tls.certificates.leaf_data.subject.common_name: "AsyncRAT Server"

#-------------------------------------------------------------------------------------
# QuasarRAT

services.tls.certificates.leaf_data.subject.common_name: {"Anony96", "Quasar Server CA"}

#-------------------------------------------------------------------------------------
# Deimos C2

same_service((services.http.response.html_title="Deimos C2" or services.tls.certificates.leaf_data.subject.organization="Acme Co") and services.port: 8443)

#-------------------------------------------------------------------------------------
# Posh C2

services.tls.certificates.leaf_data.subject_dn: "C=US, ST=Minnesota, L=Minnetonka, O=Pajfds, OU=Jethpro, CN=P18055077"

#-------------------------------------------------------------------------------------
# IcedID Banking Trojan

services.tls.certificates.leaf_data.subject_dn: "CN=localhost, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd"

#-------------------------------------------------------------------------------------
# Gozi Malware

services.tls.certificates.leaf_data.issuer_dn: "C=XX, ST=1, L=1, O=1, OU=1, CN=\*"

#-------------------------------------------------------------------------------------
# Pupy RAT C2

same_service(services.http.response.headers.Etag="\"aa3939fc357723135870d5036b12a67097b03309\"" and services.http.response.headers.Server="nginx/1.13.8") or same_service(services.tls.certificates.leaf_data.issuer.organization:/[a-zA-Z]{10}/ and  services.tls.certificates.leaf_data.subject.organization:/[a-zA-Z]{10}/ and services.tls.certificates.leaf_data.subject.organizational_unit="CONTROL")

#Note: This search uses regex and requires a paid account.

#-------------------------------------------------------------------------------------


#-------------------------------------------------------------------------------------
# Titan Stealer C2

services.http.response.body: "Titan Stealer"

#-------------------------------------------------------------------------------------
# Open Directory Listing Host with Suspicious File Names in their Contents
same_service(
    (services.http.response.html_title:"Index of /" or services.http.response.html_title:"Directory Listing for /")
    and services.http.response.body: /.*?(cve|metasploit|cobaltstrike|sliver|covenant|brc4|brute-ratel|commander-runme|bruteratel|ps2exe|(badger|shellcode|sc|beacon|artifact|payload|teamviewer|anydesk|mimikatz|cs|rclone)\.(exe|ps1|vbs|bin|nupkg)).*/
)
```

> Note: When using the `same_service` operator, the initial `services.` prefix is optional.

**Resources:**

* [TLS](https://support.censys.io/hc/en-us/articles/25499808564116-TLS)
* [Collection-1](https://github.com/thehappydinoa/awesome-censys-queries)
* [Censys Blog](https://community.censys.com/threat-hunting-38)

---

### Shodan

```bash
# jarm
ssl.jarm:""

#-------------------------------------------------------------------------------------

# favicon - mmh3
http.favicon.hash:<mmh3_hash>

#-------------------------------------------------------------------------------------

# Organization + favico
org:"orgname.com" http.favicon.hash:<mmh3_hash>

#-------------------------------------------------------------------------------------

# Filter by HTTP headers and ports to reduce noisy results

'ssl.jarm: port:"" HTTP/1.1 404 Not Found Content-Length: 0'

#-------------------------------------------------------------------------------------


```

---

### ZoomEye

New syntax is out on API v2, so some queries may need an update and some other just need to swap the `:` with `=`

Best tool: [Kunyu](https://github.com/knownsec/Kunyu)

```bash
# IP
ip:"<ip>"

#-------------------------------------------------------------------------------------

# favicon - mmh3
iconhash:"<mmh3_hash>"

#-------------------------------------------------------------------------------------

# asset with a given ssh fingerprint in a particualat time frame
"fingerprint: <ssh_rsa_fingerprint> (RSA)" && after="2023-11-06" && before="2024-11-05"

#-------------------------------------------------------------------------------------

# SSL cert fingerprint
ssl.cert.fingerprint=""

#-------------------------------------------------------------------------------------

# Header hash
http.header_hash=""

#-------------------------------------------------------------------------------------

## LockBit hunt example
# jarm filer + port + ssl data + date + Service Providers
jarm="00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01" && port=="31337" && ssl="Issuer: CN=operators" && ssl="Subject: CN=multiplayer" && after="2023–11–06" && (org="M247" || org="Artnet")

# Service Providers + OS + port + ssh banner version + date
org="M247 Ltd Amsterdam" && os=="debian" && port=="22" && "SSH-2.0-OpenSSH_8.4p1" && after="2023-11-06"


#-------------------------------------------------------------------------------------

# match unknown subdomains
hostname:".domain.co.uk" + title:"index of /"

#-------------------------------------------------------------------------------------

# ASN
asn:<asn_number> + title:"index of /" + "HTTP/1.1 200 OK"

#-------------------------------------------------------------------------------------

# Target a speific image tag in the HTML body with specific alt, width and height attributes + a fixed header value and a title of the page
("alt=\"IIS7\" width=\"571\" height=\"411\"" + "Expires: 0" + title:"IIS7")

# refined
("alt=\"IIS7\" width=\"571\" height=\"411\"" + "Expires: 0" + title:"IIS7") + (port:7777 port:7000 port:7070 port:7100) + asn:47474

```

> Note: aggregation analysis function of ZoomEye to view statistics of the search results

* Nice example of Hunting LockBit infra [link](https://medium.com/@knownsec404team/identify-infrastructure-linked-to-lockbit-3-0-ransomware-affiliates-by-zoomeye-enhanced-new-syntax-2e75b01bd978)




---

## Retrieve info

### SSL Certifiactes fingerprints etc.

```bash
# retrieve both sha1 and sha256 fingerprints also with serial number
tlsx -u domain.com -hash sha1,sha256 -se
```

### JARM Fingerprint

```shell
httpx -l target.lst -jarm
# bugged?
tlsx -u www.megacorpone.com -jarm 

# ja3
tlsx -u www.megacorpone.com -ja3
```

### Organization Name

```shell
tlsx -u hackerone.com -so
```

### Favi.ico

```shell
# mmh3 hash
httpx -favicon -u domain.com/favicon.ico

curl https://hackerone.com/favicon.ico > ico
shasum -a 256 ico
```

**Resources**

* [link-1](https://favicon-hash.kmsec.uk/)

###  SSH Fingerprint

```bash
ssh-keyscan hostname/IP -O hashalg=sha256 -D
ssh-keyscan -f hosts.txt -O hashalg=sha256 -D

nmap [SERVER] --script ssh-hostkey --script-args ssh_hostkey=all
```


### Header search (requests and responses - body)

---

## CTI Platforms

### VirusTotal

### ThreatBook

---

