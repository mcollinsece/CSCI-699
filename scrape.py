import requests
from bs4 import BeautifulSoup
import re
import pandas as pd

url = 'https://www.cisa.gov'
data = {}

# Loop through page numbers
for page in range(0, 252):  # 252 is exclusive, so it goes from 0 to 251
    print(page)
    advisory_path = f'/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A95&page={page}'
    advisory_url = url + advisory_path

    response = requests.get(advisory_url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract all anchor tags
    anchor_tags = soup.find_all('a', href=True)

    # Filter out the links that contain 'news-events/ics-advisories/'
    advisory_links = [tag['href'] for tag in anchor_tags if 'news-events/ics-advisories/' in tag['href']]

    # Process each advisory link
    for link in advisory_links:
        advisory_url = url + link
        advisory_response = requests.get(advisory_url)
        advisory_soup = BeautifulSoup(advisory_response.content, 'html.parser')

        # Find Vendor and Equipment
        vendor = equipment = None
        for li in advisory_soup.find_all('li'):
            text = li.get_text(strip=True)
            if 'Vendor:' in text:
                vendor = text.split(':', 1)[1].strip()
            elif 'Equipment:' in text:
                equipment = text.split(':', 1)[1].strip()

        # Find Affected Products
        affected_products = []
        h3 = advisory_soup.find('h3', id='31-affected-products')
        if h3:
            ul = h3.find_next('ul')
            if ul:
                for li in ul.find_all('li'):
                    affected_products.append(li.get_text(strip=True))

        # Find all links that contain 'CVE-'
        cve_urls = [cve_link['href'] for cve_link in advisory_soup.find_all('a', href=re.compile(r'CVE-\d{4}-\d+'))]

        # Store the data
        if advisory_url not in data:
            data[advisory_url] = {'Vendor': vendor, 'Equipment': equipment, 'Affected Products': affected_products, 'CVE URLs': cve_urls}
        else:
            data[advisory_url]['CVE URLs'].extend(cve_urls)

# Create a Pandas DataFrame from the dictionary
df = pd.DataFrame.from_dict(data, orient='index')

# Reset the index to make 'Advisory URL' a column
df.reset_index(inplace=True)
df.rename(columns={'index': 'Advisory URL'}, inplace=True)

# Save the DataFrame to a CSV file
df.to_csv('advisory_data.csv', index=False)

