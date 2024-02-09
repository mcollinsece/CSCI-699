from openai import OpenAI
import csv

client = OpenAI(
    # defaults to os.environ.get("OPENAI_API_KEY")
    api_key="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",
)

def query_chatgpt(description):
    try:
        completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an engineer, skilled in industrial control systems."},
            {"role": "user", "content": f"Guess the Purdue layer of the ICS device named {description}. Please only return your best guess and no other text. Example: Purdue Layer 1"}
        ]
        )
        print(completion.choices[0].message)
        return(completion.choices[0].message)
    except Exception as e:
        print(f"Error querying ChatGPT: {e}")
        return None



def main():
    input_file = './advisory_data.csv'
    output_file = 'purdue_layers.csv'

    with open(input_file, newline='', encoding='utf-8') as csvfile, open(output_file, 'w', newline='', encoding='utf-8') as outputcsv:
        reader = csv.reader(csvfile)
        writer = csv.writer(outputcsv)

        # Assuming the first row is the header
        headers = next(reader)
        writer.writerow(headers + ['Purdue Layer'])

        for row in reader:
            purdue_layer = query_chatgpt(row)
            writer.writerow(row + [purdue_layer])
            break

        

if __name__ == "__main__":
    main()

