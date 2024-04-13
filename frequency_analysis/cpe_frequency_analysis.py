import psycopg2
import pandas as pd
from scipy.stats import zscore
from sklearn.preprocessing import MinMaxScaler

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
    # SQL query to select vendor and product from cpe_entries
    query = "SELECT vendor, product FROM cpe_entries;"
    
    # Fetch data from database
    df = fetch_data(query, params)
    
    if not df.empty:
        # Calculate the frequency of each vendor and product
        vendor_counts = df['vendor'].value_counts()
        product_counts = df['product'].value_counts()

        # Calculate Z-scores and Min-Max scaling
        scaler = MinMaxScaler()
        vendor_z_scores = zscore(vendor_counts)
        product_z_scores = zscore(product_counts)
        vendor_min_max = scaler.fit_transform(vendor_counts.values.reshape(-1, 1)).flatten()
        product_min_max = scaler.fit_transform(product_counts.values.reshape(-1, 1)).flatten()

        # Prepare a DataFrame to display the results
        vendor_results = pd.DataFrame({
            'Vendor': vendor_counts.index,
            'Frequency': vendor_counts.values,
            'Z-Scores': vendor_z_scores,
            'Min-Max Scaled': vendor_min_max
        }).set_index('Vendor')

        product_results = pd.DataFrame({
            'Product': product_counts.index,
            'Frequency': product_counts.values,
            'Z-Scores': product_z_scores,
            'Min-Max Scaled': product_min_max
        }).set_index('Product')

        # Display the results in a table format
        print("Vendor Analysis:")
        print(vendor_results.head(10))
        print("\nProduct Analysis:")
        print(product_results.head(10))
    else:
        print("No data retrieved. Please check the database and query.")

if __name__ == "__main__":
    main()
