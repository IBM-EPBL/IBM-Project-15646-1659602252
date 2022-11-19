import ipaddress
import re
import socket
import traceback
import urllib.request
from datetime import date
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import requests
import whois
from bs4 import BeautifulSoup
from googlesearch import search

url = ""

def getDomainName() -> str:
    domainName = ""
    try:
        urlparser = urlparse(url)
        domainName = urlparser.netloc
    except:
        traceback.print_exc()
        raise Exception("Could not find the Domain Name")
    return domainName

def getSoupObject():
    try:
        responseObj = requests.get(url)
        soupObj = BeautifulSoup(responseObj.text, 'html.parser')
        return soupObj
    except:
        traceback.print_exc()
        raise Exception("Could not get the beatiful soup response object")


def getFeatures(URL: str) -> np.ndarray:
    global url
    url = URL

    features = [
        isHavingIp(),
        isLongURL(),
        isURLShorteningServiceUsed(),
        isAtSymbolPresent(),
        isRedirectedUsingSlashes(),
        isHyphenPresent(),
        subDomain(),
        isUsingHTTPS(),
        domainRegistrationLength(),
        isUsingNonStdPort(),
        isHTTPSInDomainPart(),
        requestURL(),
        URLOfAnchor(),
        linksInMetaScriptLinkTag(),
        serverFormHandler(),
        submittingInfoToEmail(),
        isAbnormalURL(),
        websiteForwarding(),
        statusBarCustomization(),
        isRightClickDisabled(),
        ageOfDomain(),
        checkDNSRecord(),
        websiteTraffic(),
        pageRank(),
        googleIndex(),
        linksPointingToPage(),
        statsReport()
    ]

    features = np.array(features).reshape(1, 27)
    return features

# 1. Using the IP Address
def isHavingIp() -> int:
    domainName = getDomainName()
    try:
        ipaddress.ip_address(domainName)
        print("1. Success")
        return -1
    except:
        traceback.print_exc()
        print("1. Fail")
        return 1

# 2. Long URL to Hide the Suspicious Part
def isLongURL() -> int:
    try:
        urlLength = len(url)
        print("2. Success")
        if urlLength < 54:
            return 1
        elif 54 <= urlLength <= 75:
            return 0
        return -1
    except:
        print("2. Fail")
        return 0

# 3. Using URL Shortening Services
def isURLShorteningServiceUsed() -> int:
    try:
        commonURLShorteners = [
            't\\.co', 'bitly\\.com', 'is\\.gd', 'prettylinkpro\\.com', 'cutt\\.us', 'rubyurl\\.com', 'tr\\.im',
            'v\\.gd', 'snipr\\.com', 'tinyurl', 'cli\\.gs', 'x\\.co', 'filoops\\.info', 'wp\\.me', 'q\\.gs', 't\\.co',
            'ow\\.ly', 'tiny\\.cc', 'migre\\.me', 'om\\.ly', 'bkite\\.com', 'twit\\.ac', 'db\\.tt', 'kl\\.am',
            'link\\.zip\\.net', 'x\\.co', 'u\\.bb', 'doiop\\.com', 'shorte\\.st', 'goo\\.gl', 'qr\\.net', 'u\\.to',
            'loopt\\.us', 'adf\\.ly', 'buzurl\\.com', 'post\\.ly', '1url\\.com', 'goo\\.gl', 'ff\\.im', 'short\\.ie',
            'to\\.ly', 'bit\\.ly', 'yfrog\\.com', 'yourls\\.org', 'vzturl\\.com', 'lnkd\\.in', 'ity\\.im', 'go2l\\.ink',
            'fic\\.kr', 'Just\\.as', 'su\\.pr', 'bit\\.ly', 'url4\\.eu', 'qr\\.ae', 'po\\.st', 'scrnch\\.me', 'tr\\.im',
            'twitthis\\.com', 'tweez\\.me', 'ping\\.fm', 'snipurl\\.com', 'j\\.mp', 'ow\\.ly', 'bit\\.do', 'short\\.to',
            'BudURL\\.com', 'twurl\\.nl', 'bc\\.vc', 'is\\.gd', 'tinyurl\\.com', 'cur\\.lv'
        ]
        commonURLShorteners = "|".join(commonURLShorteners)            
        isURLShortenerPresent = re.search(commonURLShorteners, url)
        print("3. Success")
        if(isURLShortenerPresent):
            return -1
        return 1
    except:
        print("3. Fail")
        return 0

# 4. URLs having “@” Symbol
def isAtSymbolPresent() -> int:
    try:
        if ( '@' in url ):
            print("4. Success")
            return -1
        print("4. Success")
        return 1
    except:
        print("4. Fail")
        return 0

# 5. Redirecting using “//”
def isRedirectedUsingSlashes() -> int:
    try:
        lastOccurenceOfDoubleSlash = -1
        if("//" in url):
            lastOccurenceOfDoubleSlash = url.rindex("//")
        if(lastOccurenceOfDoubleSlash > 6):
            print("5. Success")
            return -1
        print("5. Success")
        return 1
    except:
        print("5. Fail")
        return 0

# 6. Adding Prefix or Suffix Separated by (-) to the Domain
def isHyphenPresent() -> int:
    try:
        if ( '-' in url ):
            print("6. Success")
            return -1
        print("6. Success")
        return 1
    except:
        print("6. Fail")
        return 0

# 7. Sub Domain and Multi Sub Domains
def subDomain() -> int:
    try:
        if ( "www." in url ):
            modifiedUrl = url.replace("www.", "")
        
        # Country-Code Top Level Domains
        ccTLD = pd.read_csv("./country-codes-tlds.csv")
        ccTLD = ccTLD['tld'].to_list()
        ccTLD = [code.strip() for code in ccTLD]
        for code in ccTLD:
            if code in modifiedUrl:
                modifiedUrl = modifiedUrl.replace(code, "")
        
        dotCount = modifiedUrl.count(".")

        if dotCount <= 1:
            print("7. Success")
            return 1
        elif dotCount == 2:
            print("7. Success")
            return 0
        print("7. Success")
        return -1
    except:
        print("7. Fail")
        return 0

# 8. HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer) 
def isUsingHTTPS() -> int:
    try:
        scheme = urlparse(url).scheme
        if scheme == 'https':
            print("8. Success")
            return 1
        print("8. Success")
        return -1
    except:
        print("8. Fail")
        return 1

# 9. Domain Registration Length
def domainRegistrationLength() -> int:
    try:
        whoisResponse = whois.whois(getDomainName())

        creationDate = whoisResponse.creation_date
        expirationDate = whoisResponse.expiration_date

        try:
            if(creationDate):
                creationDate = creationDate[0]
        except:
            traceback.print_exc()

        try:
            if(expirationDate):
                expirationDate = expirationDate[0]
        except:
            traceback.print_exc()

        print(creationDate.year, creationDate.month)
        ageOfDomainInMonths = ((expirationDate.year - creationDate.year) * 12) + (expirationDate.month - creationDate.month)

        if ageOfDomainInMonths >= 12:
            print("9. Success")
            return 1
        print("9. Success")
        return -1
    except:
        traceback.print_exc()
        print("9. Fail")
        return -1

# 10. Using Non-Standard Port
def isUsingNonStdPort() -> int:
    try:
        preferredStatusOpenPorts = [80, 443]
        preferredStatusClosePorts = [21, 22, 23, 445, 1433, 1521, 3306, 3389]

        openPortsNumber, closedPortsNumber = [], []
        
        domain = getDomainName()
        
        for portNumber in preferredStatusOpenPorts + preferredStatusClosePorts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((domain, portNumber))
            if(result == 0):
                openPortsNumber.append(portNumber)
            else:
                closedPortsNumber.append(portNumber)
            sock.close

        for portNumber in openPortsNumber:
            if portNumber in preferredStatusClosePorts:
                print("10. Success")
                return -1
        print("10. Success")
        return 1
    except:
        print("10. Fail")
        return 0

# 11. The Existence of “HTTPS” Token in the Domain Part of the URL
def isHTTPSInDomainPart() -> int:
    try:
        domain = getDomainName()
        if( ("https" in domain) and ("http" in domain) ):
            print("11. Success")
            return -1
        print("11. Success")
        return 1
    except:
        print("11. Fail")
        return 0

# 12. Request URL
def requestURL() -> int:
    try:
        soupObj = getSoupObject()
        domainName = getDomainName()

        i, success = 0, 0

        for img in soupObj.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or domainName in img['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for audio in soupObj.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or domainName in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for embed in soupObj.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or domainName in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for iframe in soupObj.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or domainName in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if( percentage < 22.0 ):
                print("12. Success")
                return 1
            elif( (percentage >= 22.0) and (percentage < 61.0) ):
                print("12. Success")
                return 0
            else:
                print("12. Success")
                return -1
        except:
            print("12. Success")
            return 0
    except:
        traceback.print_exc()
        print("12. Fail")
        # return -1  
        return 0 

# 13. URL of Anchor
def URLOfAnchor() -> int:  
    try:
        i, unsafe = 0, 0
        for a in getSoupObject().find_all('a', href=True):
            if (a['href'] == "#") or ("javascript" in a['href'].lower()) or ("mailto" in a['href'].lower()) or (not (url in a['href'])) or (getDomainName() in a['href']):
                unsafe = unsafe + 1
            i += 1

        try:
            #TODO always percentage is 100. Have to check
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                print("13. Success")
                return 1
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                print("13. Success")
                return 0
            else:
                print("13. Success")
                return -1
        except:
            traceback.print_exc()
            return -1
    except:
        traceback.print_exc()
        # return -1
        print("13. Fail")
        return 0

# 14. Links in <Meta>, <Script> and <Link> tags
def linksInMetaScriptLinkTag():
    try:
        soupObj = getSoupObject()
        domainName = getDomainName()

        i, success = 0, 0
        
        for link in soupObj.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domainName in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soupObj.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domainName in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success / float(i) * 100
            if percentage < 17.0:
                print("14. Success")
                return 1
            elif((percentage >= 17.0) and (percentage < 81.0)):
                print("14. Success")
                return 0
            else:
                print("14. Success")
                return -1
        except:
            print("14. Success")
            return 0
    except:
        traceback.print_exc()
        # return -1
        print("14. Fail")
        return 0

# 15. Server Form Handler (SFH)
def serverFormHandler():
    try:
        soupObj = getSoupObject()
        domainName = getDomainName()

        if len(soupObj.find_all('form', action = True)) == 0:
            print("15. Success")
            return 1
        else :
            for form in soupObj.find_all('form', action = True):
                    if (form['action'] == "") or (form['action'] == "about:blank"):
                        print("15. Success")
                        return -1
                    elif (url not in form['action']) and (domainName not in form['action']):
                        print("15. Success")
                        return 0
                    else:
                        print("15. Success")
                        return 1
    except:
        traceback.print_exc()
        # return -1
        print("15. Fail")
        return 0

# 16. Submitting Information to Email
def submittingInfoToEmail():
    #TODO wrong
    try:
        #TODO pattern thappu
        if ( re.findall(r"mail\(\)|mailto:?", str(getSoupObject())) ):
            print("16. Success")
            return -1
        else:
            print("16. Success")
            return 1
    except:
        traceback.print_exc()
        # return -1
        print("16. Fail")
        return 0

# 17. Abnormal URL
def isAbnormalURL(): #wrong
    try:
        if (requests.get(url)).text == whois.whois(getDomainName()):
            print("17. Success")
            return 1
        else:
            print("17. Success")
            return -1
    except:
        print("17. Fail")
        return 0
        # return -1

# 18. Website Forwarding
def websiteForwarding():
    try:
        if len((requests.get(url)).history) <= 1:
            print("18. Success")
            return 1
        elif len((requests.get(url)).history) <= 4:
            print("18. Success")
            return 0
        else:
            print("18. Success")
            return -1
    except:
        print("18. Fail")
        return 0
        # return -1

# 19. Status Bar Customization
def statusBarCustomization():
    try:
        if re.findall("<script>.+onmouseover.+</script>", (requests.get(url)).text):
            print("19. Success")
            return 1
        else:
            print("19. Success")
            return -1
    except:
        print("19. Fail")
        return 0
        # return -1

# 20. Disabling Right Click
def isRightClickDisabled(): #wrong
    try:
        if re.findall(
            r"event.button ?== ?2",
            (requests.get(url)).text
        ):
            print("20. Success")
            return 1
        else:
            print("20. Success")
            return -1
    except:
        print("20. Fail")
        return 0
        # return -1

# 21. Age of Domain
def ageOfDomain() -> int:
    try:
        creationDate = whois.whois(getDomainName()).creation_date
        try:
            if(len(creationDate)):
                creationDate = creationDate[0]
        except:
            pass

        today = date.today() 
    
        domainAgeInMonths = ((today.year - creationDate.year) *12) + (today.month - creationDate.month)
        if domainAgeInMonths >= 6:
            print("21. Success")
            return 1
        print("21. Success")
        return -1
    except:
        print("21. Fail")
        return 0
        # return -1

# 22. DNS Record
def checkDNSRecord() -> int:
    try:
        whoisResponse = whois.whois(getDomainName())
        if (whoisResponse):
            print("22. Success")
            return 1
        print("22. Success")
        return -1
    except:
        print("22. Fail")
        return 0
        # return -1

# 23. Website Traffic
def websiteTraffic() -> int:
    try:
        websiteRank = BeautifulSoup(
                urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(),
                features = "xml"
            ).find("REACH")['RANK']
        if (int(websiteRank) < 100000):
            print("23. Success")
            return 1
        print("23. Success")
        return 0
    except :
        traceback.print_exc()
        print("23. Fail")
        return 0
        # return -1

# 24. PageRank
def pageRank() -> int:
    try:
        checkerResponse = requests.post("https://www.checkpagerank.net/index.php", {"name": getDomainName()})
        globalRank = int(re.findall(r"Global Rank: ([0-9]+)", checkerResponse.text)[0])
        if ( 0 < globalRank < 100000 ):
            print("24. Success")
            return 1
        print("24. Success")
        return -1
    except:
        traceback.print_exc()
        print("24. Fail")
        return 0
        # return -1

# 25. Google Index
def googleIndex() -> int:
    modifiedUrl = "site:" + url
    try:
        searchResults = search(modifiedUrl, 5)
        searchResultsList = []
        for gen in searchResults:    
            searchResultsList.append(gen)
        if searchResultsList:
            print("25. Success")
            return 1
        else:
            print("25. Success")
            return -1
    except:
        traceback.print_exc()
        print("25. Fail")
        return 0
        # return -1

# 26. Number of Links Pointing to Page
def linksPointingToPage() -> int: # Wrong
    try:
        noOfLinks = len(re.findall(r"<a href=", requests.get(url).text))
        if noOfLinks == 0:
            print("26. Success")
            return 1
        elif noOfLinks <= 2:
            print("26. Success")
            return 0
        else:
            print("26. Success")
            return -1
    except:
        print("26. Fail")
        return 0
        # return -1

# 27. Statistical-Reports Based Feature
def statsReport() -> int:
    try:
        isUrlMatched = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
            url
        )
        ip_address = socket.gethostbyname(getDomainName())
        isIpMatched = re.search(
            '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
            ip_address
        )
        if isUrlMatched:
            print("27. Success")
            return -1
        elif isIpMatched:
            print("27. Success")
            return -1
        print("27. Success")
        return 1
    except:
        print("27. Fail")
        return 0
        # return 1