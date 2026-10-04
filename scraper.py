import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def scrape_company(url):
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code != 200:
        print("Could not access website:", response.status_code)
        return

    soup = BeautifulSoup(response.text, "html.parser")

    title = soup.title.string.strip() if soup.title else "No title"

    print("\nCompany website:", url)
    print("Page title:", title)

    # Get visible text
    text = soup.get_text(" ", strip=True)

    print("\nFirst 1000 characters:")
    print(text[:1000])

    # Find links
    print("\nLinks found:")

    for link in soup.find_all("a", href=True):
        full_url = urljoin(url, link["href"])
        print(full_url)


url = input("Enter company website: ")

scrape_company(url)