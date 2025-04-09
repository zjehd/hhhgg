import requests
import socket
import datetime
import whois
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# Replace with your keys
BOT_TOKEN = "8009452297:AAHM4UIONaO3Knhn8BA9oZ_oURanLoRaq-s"
IPQS_KEY = "https://www.ipqualityscore.com/api/json/email/mLtzw7Q5RJegOI5twQlyCZyU9cl7tQY2/noreply@ipqualityscore.com?timeout=60"
URLSCAN_KEY = "019616bd-7103-719a-8bab-06566f4b1993"
VT_KEY = "78accf86048a3e4e5da3cae1af813acb1b390cc296a7135ce42c864352953cdf"
GSB_KEY = "AIzaSyCl04HnBlRzwH5G-8xAS3wRf1NHaz9IoTE"


# --- Utility Functions ---
def get_domain_age(creation_date):
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if creation_date:
        return f"{(datetime.datetime.now() - creation_date).days} days"
    return "Unknown"


def check_ipqs(url):
    # Make sure URL is properly formatted
    if not url.startswith("http"):
        url = "http://" + url

    res = requests.get(f"https://ipqualityscore.com/api/json/url/{IPQS_KEY}/{url}")
    if res.status_code == 200:
        return res.json() or {}
    else:
        print(f"IPQS Error ({res.status_code}):", res.text)
        return {"error": "IPQS failed"}


def check_virustotal(url):
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"x-apikey": VT_KEY}
    res = requests.get(f"https://www.virustotal.com/api/v3/urls", params={"url": url}, headers=headers)
    if res.status_code == 200:
        scan_data = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}).json()
        scan_id = scan_data.get("data", {}).get("id", "")
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers).json()
        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        return stats or {}
    else:
        print(f"VirusTotal Error ({res.status_code}):", res.text)
    return {}


def check_google_safebrowsing(url):
    if not url.startswith("http"):
        url = "http://" + url

    body = {
        "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    res = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
        json=body
    )
    if res.status_code == 200:
        data = res.json() or {}
        return "Unsafe" if "matches" in data else "Safe"
    else:
        print(f"SafeBrowsing Error ({res.status_code}):", res.text)
    return "Safe"


def check_ipqs(url):
    if not url.startswith("http"):
        url = "http://" + url

    res = requests.get(f"https://ipqualityscore.com/api/json/url/{IPQS_KEY}/{url}")
    if res.status_code == 200:
        data = res.json() or {}
        print("IPQS Response:", data)  # Print the raw response for debugging
        return data
    else:
        print(f"IPQS Error ({res.status_code}):", res.text)
        return {"error": "IPQS failed"}



def check_urlscan(url):
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "private"}
    res = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if res.status_code == 200:
        return res.json().get("result", "No result")
    else:
        print(f"URLScan Error ({res.status_code}):", res.text)
    return "URLScan failed"


# --- Telegram Bot Commands ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Send /check <url> to scan a website.")


async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Please provide a URL. Example:\n/check https://example.com")
        return

    url = context.args[0]
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    try:
        ip = socket.gethostbyname(domain)
        w = whois.whois(domain)
        headers = requests.head(url, timeout=10).headers

        # External API results
        ipqs = check_ipqs(url)
        vt = check_virustotal(url)
        gsb = check_google_safebrowsing(url)
        urlscan_link = check_urlscan(url)

        result = f"""
🌐 *Website Safety Report*
- Domain: `{domain}`
- IP: `{ip}`
- Server: `{headers.get('Server', 'Unknown')}`
- Domain Country: `{w.country if w.country else 'Unknown'}`
- Domain Age: `{get_domain_age(w.creation_date)}`
- Content-Language: `{headers.get('Content-Language', 'Unknown')}`
- Scan Time: `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`

🔒 *Google Safe Browsing*: `{gsb}`  
🛡️ *IPQualityScore*:
    - Risk Score: `{ipqs.get('risk_score', 'N/A')}`
    - Malware: `{ipqs.get('malware')}`
    - Phishing: `{ipqs.get('phishing', 'N/A')}`
    - Suspicious: `{ipqs.get('suspicious', 'N/A')}`
    - Adult: `{ipqs.get('adult', 'N/A')}`

🧪 *VirusTotal*:
    - Harmless: `{vt.get('harmless', '?')}`
    - Malicious: `{vt.get('malicious', '?')}`
    - Suspicious: `{vt.get('suspicious', 'halaya')}`

📸 *URLScan Result*: [View Screenshot]({urlscan_link})

🔗 Link: {url}
        """

        await update.message.reply_text(result.strip(), parse_mode="Markdown", disable_web_page_preview=False)

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error during scan:\n`{str(e)}`", parse_mode="Markdown")


def check_virustotal(url):
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"x-apikey": VT_KEY}
    res = requests.get(f"https://www.virustotal.com/api/v3/urls", params={"url": url}, headers=headers)
    if res.status_code == 200:
        scan_data = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}).json()
        scan_id = scan_data.get("data", {}).get("id", "")
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers).json()

        print("VirusTotal Response:", report)  # Print the raw response for debugging

        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        return stats or {}
    else:
        print(f"VirusTotal Error ({res.status_code}):", res.text)
    return {}


# --- App Entry Point ---
if __name__ == '__main__':
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("check", check))
    app.run_polling()
