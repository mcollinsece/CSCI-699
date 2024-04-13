import os
import psycopg2
from psycopg2 import sql
from bs4 import BeautifulSoup
import requests


# Database connection parameters - replace these with your actual parameters
db_params = {
    'dbname': 'chariots',
    'user': 'postgres',
    'password': '<insertpassword>',
    'host': 'localhost'
}

base_url = "https://cisa.gov"

def download_and_save_html(icsa, link):
    target_directory = f"/srv/html_storage/{icsa}"
    #target_directory = f"/Users/mbc/Documents/CSCI/699/html_storage/{icsa}"
    os.makedirs(target_directory, exist_ok=True)  # Create directory if it doesn't exist
    response = requests.get(f"{base_url}{link}")
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        with open(f"{target_directory}/page.html", "w", encoding='utf-8') as file:
            file.write(str(soup))
        return target_directory
    else:
        print(f"Failed to download HTML for {icsa}: Status code {response.status_code}")
        return None

def main():
    connection = psycopg2.connect(**db_params)
    cursor = connection.cursor()
    cursor.execute("SELECT id, icsa, link FROM advisory_list")
    records = cursor.fetchall()

    for record in records:
        id_, icsa, link = record
        directory_path = download_and_save_html(icsa, link)
        if directory_path:
            # Update the database with the directory path
            cursor.execute(
                sql.SQL("UPDATE advisory_list SET html_dir = %s WHERE id = %s"),
                (directory_path, id_)
            )
            connection.commit()
            print(f"Processed {icsa} successfully.")
        else:
            print(f"Failed to process {icsa}.")

    cursor.close()
    connection.close()

if __name__ == "__main__":
    main()

