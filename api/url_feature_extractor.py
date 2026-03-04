import re
import socket
import ssl
import whois
from datetime import datetime
from urllib.parse import urlparse


WHOIS_CACHE = {}


TRUSTED_DOMAINS = ["google.com", "microsoft.com", "paypal.com", "amazon.com"]
KNOWN_BRANDS = ["google", "microsoft", "paypal", "amazon", "apple", "facebook"]


def is_trusted(domain):
    return any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS)


def has_brand(domain):
    return any(brand in domain for brand in KNOWN_BRANDS)


def extract_features_from_url(url):

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Remove port if exists
    domain = domain.split(":")[0]

    features = {}

    
    features["having_IP_Address"] = -1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 1

    
    if len(url) < 54:
        features["URL_Length"] = 1
    elif 54 <= len(url) <= 75:
        features["URL_Length"] = 0
    else:
        features["URL_Length"] = -1

    
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "short.ly", "is.gd", "buff.ly"]
    features["Shortining_Service"] = -1 if any(s in domain for s in shorteners) else 1

   
    features["having_At_Symbol"] = -1 if "@" in url else 1


    url_after_protocol = url.split("://", 1)[-1]
    features["double_slash_redirecting"] = -1 if "//" in url_after_protocol else 1


    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    
    subdomain_levels = domain.split(".")
    features["having_Sub_Domain"] = -1 if len(subdomain_levels) >= 4 else 1

    
    features["HTTPS_token"] = 1 if url.startswith("https://") else -1

    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            features["SSLfinal_State"] = 1
    except Exception:
        features["SSLfinal_State"] = -1

    
    try:
        if domain in WHOIS_CACHE:
            w = WHOIS_CACHE[domain]
        else:
            w = whois.whois(domain)
            WHOIS_CACHE[domain] = w

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            features["age_of_domain"] = 1 if age_days > 365 else -1
        else:
            features["age_of_domain"] = -1

        if expiration_date and creation_date:
            reg_length_days = (expiration_date - creation_date).days
            features["Domain_registeration_length"] = 1 if reg_length_days > 365 else -1
        else:
            features["Domain_registeration_length"] = -1

    except Exception:
        features["age_of_domain"] = -1
        features["Domain_registeration_length"] = -1

    
    try:
        socket.gethostbyname(domain)
        features["DNSRecord"] = 1
    except Exception:
        features["DNSRecord"] = -1

    
    port = parsed.port
    STANDARD_PORTS = [80, 443, None]
    features["port"] = -1 if port not in STANDARD_PORTS else 1

    
    if has_brand(domain) and not is_trusted(domain):
        features["Google_Index"] = -1
    elif is_trusted(domain):
        features["Google_Index"] = 1
    else:
        features["Google_Index"] = 0

    
    if is_trusted(domain):
        features["web_traffic"] = 1
        features["Page_Rank"] = 1
    else:
        features["web_traffic"] = 0
        features["Page_Rank"] = 0

    
    ALL_FEATURES = [
        "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
        "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
        "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
        "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
        "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
        "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
        "Statistical_report"
    ]

    
    for f in ALL_FEATURES:
        if f not in features:
            features[f] = 0

    
    print("FEATURE VECTOR:", features)

    return features