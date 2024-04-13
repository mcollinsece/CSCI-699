import os
import re
from bs4 import BeautifulSoup
from collections import Counter
import psycopg2


def save_to_database(cve_to_icsas, db_params):
    """Save the CVE and ICSA data to the database."""
    try:
        # Connect to your database
        conn = psycopg2.connect(**db_params)
        cursor = conn.cursor()

        # Iterate over the CVE to ICSA mappings
        for cve, icsas in cve_to_icsas.items():
            # Insert the CVE into the cve_list table, ignore duplicates
            cursor.execute("INSERT INTO cve_list (cve_id) VALUES (%s) ON CONFLICT (cve_id) DO NOTHING", (cve,))

            # Iterate over ICSAs associated with this CVE
            for icsa in icsas:
                # Insert each CVE and ICSA into the cve_icsa_join table
                cursor.execute("INSERT INTO cve_icsa_join (cve_id, icsa) VALUES (%s, %s) ON CONFLICT DO NOTHING", (cve, icsa))

        # Commit the transaction
        conn.commit()

        # Close the database connection
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Database operation failed: {e}")


def find_cves_in_html(html_content):
    """Find all unique CVE mentions in the HTML content."""
    soup = BeautifulSoup(html_content, 'lxml')
    # This regex matches strings like CVE-1999-0067 or CVE-2022-1234
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cves = set(re.findall(cve_pattern, soup.get_text()))
    return cves

def scan_directories_for_cves(base_path='/srv/html_storage'):
    """Scan directories and subdirectories for CVE references in page.html files."""
    cve_references = set()
    for root, dirs, files in os.walk(base_path):
        if 'page.html' in files:
            # Extract the ICSA identifier from the root path
            icsa = os.path.basename(root).strip()
            file_path = os.path.join(root, 'page.html')
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    html_content = file.read()
                    cves = find_cves_in_html(html_content)
                    # Update to save tuples of (icsa, cve)
                    for cve in cves:
                        cve_references.add((icsa, cve))
            except Exception as e:
                print(f"Failed to process {file_path}: {e}")
    return cve_references



if __name__ == "__main__":
    db_params = {
        'dbname': 'chariots',
        'user': 'postgres',
        'password': '<insertpassword>',
        'host': 'localhost'
    }

    cves_found = scan_directories_for_cves()
    cve_to_icsas = {}

    count = 0
    for icsa, cve in cves_found:
        cve_to_icsas.setdefault(cve, set()).add(icsa)
        count += 1
    print("Number found: " + str(count))

    for cve in cve_to_icsas:
        cve_to_icsas[cve] = list(cve_to_icsas[cve])

    # Save to database
    save_to_database(cve_to_icsas, db_params)
    print("Done")
