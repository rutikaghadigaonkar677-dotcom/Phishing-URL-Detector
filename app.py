
import os
import requests
import socket
import sqlite3
from flask import Flask, request, render_template
from urllib.parse import urlparse

app = Flask(__name__, template_folder=".", static_folder=".", static_url_path="/static")
def init_db():
    conn = sqlite3.connect("contact_messages.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


init_db()

def check_with_safe_browsing(url):
    api_key = os.getenv("SAFE_BROWSING_API_KEY")

    if not api_key:
        return None, "API key not configured"

    api_url = (
        "https://safebrowsing.googleapis.com/"
        "v4/threatMatches:find"
    )

    payload = {
        "client": {
            "clientId": "phishing-url-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            api_url,
            params={"key": api_key},
            json=payload,
            timeout=10
        )

        if response.status_code != 200:
            return None, (
                f"API request failed ({response.status_code}): "
                f"{response.text[:300]}"
            )

        data = response.json()

        if data.get("matches"):
            return True, "Known threat found"

        return False, "No known threat found"

    except requests.RequestException:
        return None, "Unable to connect to API"

@app.route("/")
def home():
    return render_template("index.html")
   
@app.route("/about.html")
def about():
    return render_template("about.html")


@app.route("/safety.html")
def safety():
    return render_template("safety.html")


@app.route("/faq.html")
def faq():
    return render_template("faq.html")


@app.route("/contact.html")
def contact():
    return render_template("contact.html")


@app.route("/check", methods=["POST"])
def check_url():
    url = request.form.get("url", "").strip()

    if not url:
        return "<h1>Please enter a URL.</h1>"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Check URL format first
    if (
        not domain
        or "." not in domain
        or any(char.isspace() for char in url)
    ):
        return """
        <div style="font-family:Arial; max-width:500px; margin:40px auto;
                    padding:30px; text-align:center; background:#eff6ff;
                    border:1px solid #bfdbfe; border-radius:16px;">
            <div style="font-size:48px;">🔗</div>
            <h2 style="color:#1d4ed8;">Invalid URL</h2>
            <p style="color:#1e40af;">
                Please enter a valid website address.
            </p>
        </div>
        """

    # Check whether the domain resolves through DNS
    try:
        socket.getaddrinfo(domain, None)
    except socket.gaierror:
        return """
        <div style="font-family:Arial; max-width:500px; margin:40px auto;
                    padding:30px; text-align:center; background:#fff7ed;
                    border:1px solid #fed7aa; border-radius:16px;">
            <div style="font-size:48px;">🌐</div>
            <h2 style="color:#c2410c;">Website Not Found</h2>
            <p style="color:#9a3412;">
                We couldn't find this website. Please check the domain name.
            </p>
        </div>
        """

    is_threat, message = check_with_safe_browsing(url)

    if is_threat is True:
        return f"""
        <div style="font-family:Arial; max-width:500px; margin:40px auto;
                    padding:30px; text-align:center; background:#fef2f2;
                    border:1px solid #fecaca; border-radius:16px;">
            <div style="font-size:48px;">🛡️</div>
            <h2 style="color:#dc2626;">Potentially Dangerous</h2>
            <p style="color:#991b1b;">A known threat was detected for this URL.</p>
            <div style="background:white; padding:12px; border-radius:8px;
                        overflow-wrap:anywhere;">{url}</div>
        </div>
        """

    if is_threat is False:
        return f"""
        <div style="font-family:Arial; max-width:500px; margin:40px auto;
                    padding:30px; text-align:center; background:#f0fdf4;
                    border:1px solid #bbf7d0; border-radius:16px;">
            <div style="font-size:48px;">🛡️</div>
            <h2 style="color:#15803d;">No Known Threat Found</h2>
            <p style="color:#166534;">URL checked successfully</p>
            <div style="background:white; padding:12px; border-radius:8px;
                        overflow-wrap:anywhere;">{url}</div>
        </div>
        """

    return f"""
    <h1>Unable to Verify</h1>
    <p>{message}</p>
    <p>Please try again later.</p>
    """
    
@app.route("/contact", methods=["POST"])
def contact_submit():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    message = request.form.get("message", "").strip()

    if not name or not email or not message:
        return "<h2>Please fill in all fields.</h2>"

    return f"""
    <div style="font-family:Arial; max-width:500px; margin:40px auto;
                padding:30px; text-align:center; background:#f0fdf4;
                border:1px solid #bbf7d0; border-radius:16px;">
        <div style="font-size:48px;">✅</div>
        <h2 style="color:#15803d;">Message Submitted Successfully!</h2>
        <p>Thank you, {name}! Your message has been received.</p>
        <p style="color:#166534;">
            
        </p>
        <a href="/contact.html">Back to Contact Us</a>
    </div>M
    """



if __name__ == "__main__":
    app.run(debug=True)
      
