import csv
import matplotlib.pyplot as plt
from collections import Counter
import mplcursors

def parse_csv(file_name):
    """ Parse the CSV file and return a list of vendors. """
    vendors = []
    with open(file_name, mode='r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Skip the header row
        for row in csv_reader:
            if row:  # Check if row is not empty
                vendors.append(row[1])  # Append the vendor name
    return vendors

def create_histogram(vendors):
    """ Create a histogram with logarithmic Y-axis, without X-axis labels, and ordered by frequency. """
    vendor_counts = Counter(vendors)

    # Sort vendors by frequency in descending order
    sorted_vendors = sorted(vendor_counts.items(), key=lambda item: item[1], reverse=True)
    labels, counts = zip(*sorted_vendors)  # Unzip into two lists

    # Create the histogram
    plt.figure(figsize=(10, 6))
    plt.bar(labels, counts)
    plt.xlabel('Vendor')
    plt.ylabel('Frequency (log scale)')
    plt.yscale('log')  # Set Y-axis to logarithmic scale
    plt.title('Frequency of Vendors in CSV')

    # Remove X-axis labels
    plt.xticks([])

    # Add hover functionality
    mplcursors.cursor(hover=True)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    file_name = 'advisory_data.csv'  # Replace with your CSV file path
    vendors = parse_csv(file_name)
    create_histogram(vendors)
