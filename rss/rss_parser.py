import os
import time
from datetime import datetime
import feedparser
import psycopg2
from psycopg2.extras import execute_values
from contextlib import closing
from bs4 import BeautifulSoup
import re
import requests
import json

# RSS Feed URL
RSS_URL = 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml'
API_KEY = "<insertAPIKey>"

DB_PARAMS = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': '<insertPassword>',
    'host': 'ics_db',
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
        print(f"Failed to initialize database: {e}", flush=True)
        raise

def save_cve_details(cve_details):
    """Save CVE details to the database, handling potentially missing values."""
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()

        insert_query = """
        INSERT INTO cve_list(
            "cve_id", "results_per_page", "start_index", "total_results", "format", "version", 
            "timestamp", "source_identifier", "published", "last_modified", "vuln_status", 
            "descriptions", "metrics_v31", "metrics_v2", "weaknesses", "configurations", "references"
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT ("cve_id") DO UPDATE SET
            "results_per_page" = EXCLUDED."results_per_page",
            "start_index" = EXCLUDED."start_index",
            "total_results" = EXCLUDED."total_results",
            "format" = EXCLUDED."format",
            "version" = EXCLUDED."version",
            "timestamp" = EXCLUDED."timestamp",
            "source_identifier" = EXCLUDED."source_identifier",
            "published" = EXCLUDED."published",
            "last_modified" = EXCLUDED."last_modified",
            "vuln_status" = EXCLUDED."vuln_status",
            "descriptions" = EXCLUDED."descriptions",
            "metrics_v31" = EXCLUDED."metrics_v31",
            "metrics_v2" = EXCLUDED."metrics_v2",
            "weaknesses" = EXCLUDED."weaknesses",
            "configurations" = EXCLUDED."configurations",
            "references" = EXCLUDED."references";
        """

        # Safely extract vulnerability information with default values for potentially missing data
        vuln = cve_details.get('vulnerabilities', [{}])[0].get('cve', {})
        
        # Serialize complex fields with defaults for missing data
        descriptions = json.dumps([d['value'] for d in vuln.get('descriptions', [])])
        metrics_v31 = json.dumps(vuln.get('metrics', {}).get('cvssMetricV31', [{}]))
        metrics_v2 = json.dumps(vuln.get('metrics', {}).get('cvssMetricV2', [{}]))
        weaknesses = json.dumps([{"source": w.get('source', ''), "description": w.get('description', [{}])[0].get('value', '')} for w in vuln.get('weaknesses', [])])
        configurations = json.dumps(vuln.get('configurations', {}))
        references = json.dumps([r.get('url', '') for r in vuln.get('references', [])])
        
        # Execute the insert query with all necessary parameters and default values for missing data
        cur.execute(insert_query, (
            vuln.get('id', ''), cve_details.get('resultsPerPage', 0), cve_details.get('startIndex', 0),
            cve_details.get('totalResults', 0), cve_details.get('format', ''), cve_details.get('version', ''),
            cve_details.get('timestamp', None), vuln.get('sourceIdentifier', ''), vuln.get('published', None),
            vuln.get('lastModified', None), vuln.get('vulnStatus', ''), descriptions, metrics_v31,
            metrics_v2, weaknesses, configurations, references
        ))

        conn.commit()
        cur.close()
        conn.close()
        print("Data written to PostgreSQL Table", flush=True)
    except psycopg2.Error as e:
        print(f"Database error: {e}", flush=True)
    except Exception as e:
        print(f"An error occurred: {e}", flush=True)

def fetch_cve_details(cve_id):
    """
    Fetch CVE details from the NVD API using an API key.
    
    Notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.
    """
    # API key is now correctly passed in the header, adhering to the case sensitivity note.
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        'apiKey': API_KEY  # Header name is case-sensitive and follows the provided format.
    }
    try:
        response = requests.get(url, headers=headers)
        # Handling HTTP status codes according to the provided guidelines.
        if response.status_code == 200:
            data = response.json()
            # Handling the case where the request succeeds but no data is returned.
            if not data.get('vulnerabilities'):
                print(f"No data found for {cve_id}.", flush=True)
                return None
            return data
        else:
            # Extracting and printing the error message from the response header if available.
            error_message = response.headers.get('message', 'No specific error message provided.')
            print(f"Failed to fetch details for {cve_id}. Status code: {response.status_code}. Error: {error_message}", flush=True)
    except requests.RequestException as e:
        print(f"HTTP request error: {e}", flush=True)

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
        print(directory_path, flush=True)
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
                cve_details = fetch_cve_details(cve)
                # Insert the CVE into the cve_list table, ignore duplicates
                #cur.execute("INSERT INTO cve_list (cve_id) VALUES (%s) ON CONFLICT (cve_id) DO NOTHING", (cve,))
                save_cve_details(cve_details)
                time.sleep(1)

                unique_icsas = set(icsas)  # Remove duplicates of ICSAs for the current CVE

                # Iterate over unique ICSAs associated with this CVE
                for icsa in unique_icsas:
                    # Insert each CVE and ICSA into the cve_icsa_join table
                    cur.execute("INSERT INTO cve_icsa_join (cve_id, icsa) VALUES (%s, %s) ON CONFLICT DO NOTHING", (cve, icsa))

        conn.commit()

    print(f"Entries inserted or skipped: {len(entries)}", flush=True)

#Ensure the rest of your script (RSS_URL definition, etc.) remains unchanged
if __name__ == "__main__":
    init_db()
    while True:
        fetch_and_update()
        print("Sleeping for 1 hour...", flush=True)
        time.sleep(3600)  # Sleep for 1 hour
