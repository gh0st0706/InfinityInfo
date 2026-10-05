import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


# Ask for the company website
url = input("Enter company website: ").strip()

# Add https:// if the user didn't type it
if not url.startswith(("http://", "https://")):
    url = "https://" + url


# Download the website
try:
    response = requests.get(
        url,
        headers={
            "User-Agent": "Mozilla/5.0"
        },
        timeout=10
    )

    response.raise_for_status()

except requests.RequestException as error:
    print("Could not access website:")
    print(error)
    exit()


# Parse HTML
soup = BeautifulSoup(response.text, "html.parser")


# Get page title
title = soup.title.string.strip() if soup.title else "No title found"


# Remove unnecessary elements
for element in soup(["script", "style", "noscript"]):
    element.decompose()


# Get readable text
text = soup.get_text(" ", strip=True)


# Find emails
emails = re.findall(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    text
)


# Find Indian phone numbers
phones = re.findall(
    r"(?:\+91[\s-]?)?[6-9]\d{9}",
    text
)


# Find links
links = []

for link in soup.find_all("a", href=True):
    href = link["href"]

    # Convert relative links into complete URLs
    full_url = urljoin(url, href)

    links.append(full_url)


# Only keep links belonging to the same website
base_domain = urlparse(url).netloc

internal_links = []

for link in links:
    link_domain = urlparse(link).netloc

    if link_domain == base_domain:
        internal_links.append(link)


# Keywords useful for finding company information
useful_keywords = [
    "about",
    "company",
    "business",
    "product",
    "products",
    "service",
    "services",
    "contact",
    "export",
    "industry"
]


# Filter useful links
useful_links = []

for link in internal_links:

    link_lower = link.lower()

    if any(keyword in link_lower for keyword in useful_keywords):
        useful_links.append(link)


# Remove duplicates
emails = sorted(set(emails))
phones = sorted(set(phones))
useful_links = sorted(set(useful_links))


# Display results
print("\n" + "=" * 50)
print("COMPANY SCRAPER")
print("=" * 50)

print("\nCompany website:")
print(url)

print("\nPage title:")
print(title)

print("\nFirst 1000 characters:")
print(text[:1000])


print("\nEmails found:")

if emails:
    for email in emails:
        print(email)
else:
    print("None found")


print("\nPhone numbers found:")

if phones:
    for phone in phones:
        print(phone)
else:
    print("None found")


print("\nUseful internal links:")

if useful_links:
    for link in useful_links:
        print(link)
else:
    print("None found")


print("\nTotal internal links:", len(set(internal_links)))
print("Useful links:", len(useful_links))

print("\n" + "=" * 50)