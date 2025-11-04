import pandas as pd
import requests
import json
import os

# 1. Load the Excel sheet to get all domains




# 2. Load the API key from your JSON file
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"configuration.json")) as f:
    configuration=json.load(f)
    api_key = configuration["API_KEY"]
    excel_path = configuration["Domain_Database"]

df = pd.read_excel(excel_path,sheet_name="Sheet1")
domains = df['Whitelisted Domains'].dropna().tolist()


headers = {"API-Key": api_key}

# 3. For each domain, fetch URLs and save to a CSV
for domain in domains:
    all_urls = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Error for domain {domain}: {response.status_code} {response.text}")
            break
        data = response.json()
        for result in data.get('results', []):
            u = result['page'].get('url')
            if u:
                all_urls.add(u)
        url = data.get('next')  # Paging link if more results

    # Save to CSV (skip if none found)
    if all_urls:
        csv_filename = f"{domain.replace('.', '_')}.csv"
        pd.DataFrame({"url": list(all_urls)}).to_csv(csv_filename, index=False)
        print(f"Saved {len(all_urls)} URLs to {csv_filename}")
    else:
        print(f"No URLs found for {domain}")
