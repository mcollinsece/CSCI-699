import psycopg2
import pandas as pd

# Database connection parameters
params = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': 'DrBanikIsAwesome',
    'host': '24.192.91.200',
    'port': 5432
}

def fetch_data(query, params):
    """
    Fetch data from the PostgreSQL database and return as a DataFrame.
    """
    try:
        # Connect to the database
        conn = psycopg2.connect(**params)
        # Create a new cursor
        cur = conn.cursor()
        # Execute the query
        cur.execute(query)
        # Fetch the results
        rows = cur.fetchall()
        # Get the column names
        columns = [desc[0] for desc in cur.description]
        # Close the cursor and connection
        cur.close()
        conn.close()
        # Create a DataFrame from the fetched data
        return pd.DataFrame(rows, columns=columns)
    except psycopg2.Error as e:
        print("Database connection error:", e)
        return pd.DataFrame()

def main():









    # # Query to join cpe_entries with cve_list and get the needed data
    # join_query = """
    # SELECT ce.vendor, cl.cvss_score
    # FROM cpe_entries ce
    # JOIN cve_list cl ON ce.cve_id = cl.cve_id;
    # """
    
    # # Fetch the joined data
    # data_df = fetch_data(join_query, params)

    # if not data_df.empty:
    #     # Group by vendor and sum the CVSS scores to get a weighted score
    #     vendor_scores = data_df.groupby('vendor')['cvss_score'].sum().reset_index()
    #     # Sort the vendors by their scores in descending order
    #     vendor_scores.sort_values(by='cvss_score', ascending=False, inplace=True)
    #     vendor_scores.rename(columns={'cvss_score': 'Total_CVSS_Score'}, inplace=True)

    #     # Display the results
    #     print("Vendor Rankings by CVSS Score:")
    #     print(vendor_scores)
    # else:
    #     print("No data retrieved. Please check the database and query.")

if __name__ == "__main__":
    main()
