import re

def extract_urls(email_text):
    """
    Extract URLs from raw email text using regex.
    """
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, email_text)
    return urls


if __name__ == "__main__":
    sample_email = """
    Dear user,
    Please verify your account immediately:
    http://secure-login-paypal.xyz
    """

    found_urls = extract_urls(sample_email)
    print("Extracted URLs:", found_urls)