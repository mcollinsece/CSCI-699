import psycopg2

# Database connection parameters
params = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': '<insertpassword>',
    'host': 'ics_db',
    'port': 5432
}

# Connect to the PostgreSQL database
conn = psycopg2.connect(**params)
cur = conn.cursor()

count = 0

try:
    # Query to fetch CVE IDs and configurations
    cur.execute("SELECT cve_id, configurations FROM cve_list")
    cve_data = cur.fetchall()

    # Iterate over each entry in the cve_list
    for cve_id, configurations in cve_data:
        if configurations is None:
            continue  # Skip if configurations is None
        for config in configurations:
        # configurations is already a dictionary, no need to iterate over it as a list
        # Navigate through the JSON structure
            for node in config.get("nodes", []):
                if node is None:
                    continue  # Skip if node is None
                for cpeMatch in node.get("cpeMatch", []):
                    if cpeMatch is None:
                        continue  # Skip if cpeMatch is None

                    # Extract necessary fields from each CPE match
                    criteria = cpeMatch.get("criteria")
                    if criteria is None:
                        continue  # Skip if criteria is missing

                    #print(criteria)
                    #print("%%%%%%%%%%%")

                    # Splitting the criteria string by ':', taking the cpe_version directly after 'cpe'
                    parts = criteria.split(":")
                    #print(len(parts))
                    if len(parts) < 11:
                        continue  # Ensure there are enough parts to unpack, expecting at least 11 parts based on your format

                    cpe_version, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other, *_ = parts[1:13]  # Adjusted to get specific parts
                    #print(cpe_version, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other)

                    # Check if the entry exists
                    check_query = """
                    SELECT 1 FROM cpe_entries
                    WHERE cpe_version = %s AND part = %s AND vendor = %s AND product = %s AND version = %s AND update = %s AND edition = %s AND language = %s AND sw_edition = %s AND target_sw = %s AND target_hw = %s AND other = %s;
                    """
                    cur.execute(check_query, (cpe_version, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other))
                    exists = cur.fetchone()

                    if not exists:
                        count += 1
                        print(count)
                        # Insert data into cpe_entries table if it does not exist
                        insert_query = """
                        INSERT INTO cpe_entries (cve_id, cpe_version, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """
                        cur.execute(insert_query, (cve_id, cpe_version, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other))

    # Commit the changes
    conn.commit()

except Exception as e:
    print(f"An error occurred: {e}")
    conn.rollback()

finally:
    # Close communication with the database
    cur.close()
    conn.close()
