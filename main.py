import os
import time
import pandas as pd
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

# === Date-based filenames ===
today = datetime.now()
csv_filename = today.strftime("%m_%y_%d.csv")
md_filename = today.strftime("%m_%y_%d.md")

# === ChromeDriver path ===
CHROME_DRIVER_PATH = "/Users/ankitapatra/Desktop/Cyber/chromedriver"

# === Selenium setup ===
options = Options()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")

driver = webdriver.Chrome(service=Service(CHROME_DRIVER_PATH), options=options)

# === Target URL ===
url = "https://app.crowdsec.net/cti?q=classifications.classifications.name%3A%22profile%3Aweb_hosting%22+AND+%28reputation%3Amalicious+OR+reputation%3Asuspicious%29&page=1"

print("🌐 Opening CrowdSec CTI page...")
driver.get(url)
time.sleep(15)  # Wait for JS to render

# === Extract table data ===
print("🔍 Scraping data from page...")
all_data = []

entries = driver.find_elements(By.CSS_SELECTOR, ".cti-result-item")

for entry in entries:
    try:
        ip = entry.find_element(By.CSS_SELECTOR, ".ip-address").text
        location = entry.find_element(By.CSS_SELECTOR, ".location").text
        datetime_text = entry.find_element(By.CSS_SELECTOR, ".last-seen").text
        site = entry.find_element(By.CSS_SELECTOR, ".site").text

        date, time_ = "", ""
        if " " in datetime_text:
            date, time_ = datetime_text.split(" ", 1)

        all_data.append({
            "IP Address": ip,
            "Location": location,
            "Date": date,
            "Time": time_,
            "Site": site
        })

    except Exception as e:
        print(f"⚠️ Skipping row: {e}")

driver.quit()

# === Save CSV + Markdown ===
if all_data:
    df = pd.DataFrame(all_data, columns=["IP Address", "Location", "Date", "Time", "Site"])
    df.to_csv(csv_filename, index=False)
    print(f"✅ CSV saved as: {csv_filename}")

    with open(md_filename, "w") as f:
        f.write("| IP Address | Location | Date | Time | Site |\n")
        f.write("| ---------- | -------- | ---- | ---- | ---- |\n")
        for _, row in df.iterrows():
            f.write(f"| {row['IP Address']} | {row['Location']} | {row['Date']} | {row['Time']} | {row['Site']} |\n")

    print(f"✅ Markdown saved as: {md_filename}")
else:
    print("⚠️ No entries found — check page or selectors.")
