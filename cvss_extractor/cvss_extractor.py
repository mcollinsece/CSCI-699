import psycopg2

# Database connection parameters
params = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': '<insertpassword>',
    'host': '<inserthost>',
    'port': 5432
}

# Connect to the PostgreSQL database
conn = psycopg2.connect(**params)
cur = conn.cursor()

# Initialize a dictionary to store cve_id and baseScore
scores_dict = {}

try:
    # Query to fetch CVE IDs and configurations
    cur.execute("SELECT cve_id, metrics_v2, metrics_v31 FROM cve_list")
    cve_data = cur.fetchall()

    # Iterate over each entry in the cve_list
    for cve_id, metrics_v2, metrics_v31 in cve_data:
        # Determine which metric set to use; prefer v31 if not None and not empty
        if metrics_v31 and metrics_v31 != [{}]:
            metrics = metrics_v31[0]  # Assume we want the first entry if present
        elif metrics_v2 and metrics_v2 != [{}]:
            metrics = metrics_v2[0]  # Use v2 if v31 is not available or empty
        else:
            continue  # Skip to next record if both are None or empty

        # Access 'cvssData' if it exists and is not None
        cvss_data = metrics.get('cvssData')
        if cvss_data:
            base_score = cvss_data.get('baseScore')
            if base_score is not None:  # Ensure baseScore exists
                # Store the score with the CVE ID in the dictionary
                scores_dict[cve_id] = base_score

    # Print the length of the dictionary containing the scores
    print("Number of entries with scores:", len(scores_dict))


    # Step 1: Add a new column 'cvss_score' to the 'cve_list' table if it does not already exist
    cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cve_list' and column_name='cvss_score') THEN
            ALTER TABLE cve_list ADD COLUMN cvss_score DECIMAL;
        END IF;
    END
    $$;
    """)

    # Step 2: Update the table with values from scores_dict
    for cve_id, score in scores_dict.items():
        cur.execute("UPDATE cve_list SET cvss_score = %s WHERE cve_id = %s", (score, cve_id))

    # Commit changes
    conn.commit()

except Exception as e:
    print(f"An error occurred: {e}")
    conn.rollback()

finally:
    # Close communication with the database
    cur.close()
    conn.close()
