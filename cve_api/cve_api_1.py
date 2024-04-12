import psycopg2
import requests
import json
import time

# Database connection parameters
DB_PARAMS = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': '<insert_password>',
    'host': 'ics_db',  
    'port': 5432
}

def fetch_cve_ids():
    """Fetch all CVE IDs from the database."""
    cve_ids = []
    try:
        # Connect to the database
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()
        # Execute the query
        cur.execute("SELECT cve_id FROM cve_list;")
        # Fetch all the results
        cve_ids = [row[0] for row in cur.fetchall()]
        # Close the database connection
        cur.close()
        conn.close()
    except psycopg2.Error as e:
        print(f"Database error: {e}")
    return cve_ids

def fetch_cve_details(cve_id):
    """
    Fetch CVE details from the NVD API using an API key.
    
    Notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.
    """
    # API key is now correctly passed in the header, adhering to the case sensitivity note.
    api_key = "<insert_apiKey>"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        'apiKey': api_key  # Header name is case-sensitive and follows the provided format.
    }
    
    try:
        response = requests.get(url, headers=headers)
        # Handling HTTP status codes according to the provided guidelines.
        if response.status_code == 200:
            data = response.json()
            # Handling the case where the request succeeds but no data is returned.
            if not data.get('vulnerabilities'):
                print(f"No data found for {cve_id}.")
                return None
            return data
        else:
            # Extracting and printing the error message from the response header if available.
            error_message = response.headers.get('message', 'No specific error message provided.')
            print(f"Failed to fetch details for {cve_id}. Status code: {response.status_code}. Error: {error_message}")
    except requests.RequestException as e:
        print(f"HTTP request error: {e}")

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
        print("Data written to PostgreSQL Table")
    except psycopg2.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")



def main():
    cve_ids = fetch_cve_ids()
    if cve_ids:
        print(f"Found {len(cve_ids)} CVE IDs. Fetching details...")
        count = 0
        for cve_id in cve_ids:
            cve_details = fetch_cve_details(cve_id)
            print(cve_id)
            count += 1
            print(count)
            save_cve_details(cve_details)
            time.sleep(1)
    else:
        print("No CVE IDs found.")

if __name__ == "__main__":
    main()
