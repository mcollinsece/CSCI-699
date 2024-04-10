import os
import time
from datetime import datetime
import feedparser
import psycopg2
from psycopg2.extras import execute_values
from contextlib import closing
from bs4 import BeautifulSoup
import re

# RSS Feed URL
RSS_URL = 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml'

DB_PARAMS = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': '<insertpassword>',
    'host': 'ics_db',
    #'host': '24.192.91.200',
    'port': 5432
}

def init_db():
    try:
        with closing(psycopg2.connect(**DB_PARAMS)) as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS advisory_list (
                        id SERIAL PRIMARY KEY,
                        date VARCHAR(255),
                        title TEXT,
                        icsa TEXT UNIQUE,
                        link TEXT UNIQUE,
                        html_dir TEXT,
                        vendor VARCHAR(255)
                    )
                ''')
            conn.commit()
    except Exception as e:
        print(f"Failed to initialize database: {e}")
        raise

def fetch_and_update():
    feed = feedparser.parse(RSS_URL)
    entries = []
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")  # Regular expression pattern for CVE identifiers
    cve_to_icsas = {}

    for entry in feed.entries:
        original_date = datetime.strptime(entry.published, '%a, %d %b %y %H:%M:%S %z')
        formatted_date = original_date.strftime('%b %d, %Y')
        title = entry.title
        # Assuming the link is a complete URL and you wish to store the path part only
        link_path = entry.link.split("https://www.cisa.gov")[-1]
        advisory_number = link_path.split("/")[-1]

        # Parse the summary HTML to find the vendor name
        soup = BeautifulSoup(entry.summary, 'html.parser')

        # Set vendor to default of unkown
        vendor = "Unknown"

        #Find all CVEs in HTML
        cves_found = set(cve_pattern.findall(entry.summary) + cve_pattern.findall(title))  # Search in summary and title
        
        # Map each found CVE to its corresponding ICSA advisory number
        for cve in cves_found:
            if cve not in cve_to_icsas:
                cve_to_icsas[cve] = []
            cve_to_icsas[cve].append(advisory_number)

        for li in soup.find_all('li'):
            if 'Vendor' in li.text:
                vendor_text = li.get_text()
                vendor = vendor_text.split(':', 1)[1].strip() if ':' in vendor_text else vendor_text.strip()
                break

        # The rest of your code to set up the directory and parse other data
        directory_path = f"/srv/html_storage/{advisory_number}"
        print(directory_path)
        os.makedirs(directory_path, exist_ok=True)
        with open(os.path.join(directory_path, "page.html"), "w") as file:
            file.write(entry.summary)
        
        entries.append((formatted_date, title, advisory_number, link_path, directory_path, vendor))
    
    with closing(psycopg2.connect(**DB_PARAMS)) as conn:
        with conn.cursor() as cur:
            # Assuming 'entries' is prepared beforehand
            execute_values(cur,
                           '''
                           INSERT INTO advisory_list (date, title, icsa, link, html_dir, vendor)
                           VALUES %s ON CONFLICT (link) DO NOTHING
                           ''',
                           entries)

            for cve, icsas in cve_to_icsas.items():
                # Insert the CVE into the cve_list table, ignore duplicates
                cur.execute("INSERT INTO cve_list (cve_id) VALUES (%s) ON CONFLICT (cve_id) DO NOTHING", (cve,))

                unique_icsas = set(icsas)  # Remove duplicates of ICSAs for the current CVE

                # Iterate over unique ICSAs associated with this CVE
                for icsa in unique_icsas:
                    # Insert each CVE and ICSA into the cve_icsa_join table
                    cur.execute("INSERT INTO cve_icsa_join (cve_id, icsa) VALUES (%s, %s) ON CONFLICT DO NOTHING", (cve, icsa))

        conn.commit()

    print(f"Entries inserted or skipped: {len(entries)}")

#Ensure the rest of your script (RSS_URL definition, etc.) remains unchanged
if __name__ == "__main__":
    init_db()
    while True:
        fetch_and_update()
        print("Sleeping for 1 hour...")
        time.sleep(3600)  # Sleep for 1 hour
