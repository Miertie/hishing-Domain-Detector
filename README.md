# 🎣 Phishing Domain & URL Detector

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Phishing%20Analysis-red?style=for-the-badge)

A multi-layered threat intelligence tool built with Python and Streamlit that evaluates suspicious URLs and domain names for phishing indicators through real-time lexical inspection, WHOIS registration tracking, and SSL certificate verification.

---

## 📸 Screenshots & Code Showcase

### 1. Application Interface & Risk Scoring
![App Interface](assets/demo1.png)

### 2. Code Implementation & Inspection Engine
![Code Showcase](assets/demo2.png)

---

## ✨ Key Features

* **Lexical Anatomy Analysis:** Detects IP-based hostnames, excessive subdomains (`paypal.com.attacker.com`), `@` symbol redirects, and URL length anomalies.
* **WHOIS Domain Age Verification:** Queries domain registration records to flag newly created domains (<30 days old), which account for over 70% of active phishing sites.
* **Credential Harvesting Detection:** Scans URL structures for high-risk targeting keywords (`login`, `verify`, `banking`, `secure`, `update`).
* **SSL/TLS Validation:** Performs socket-level handshakes on port 443 to verify HTTPS availability and certificate issuer authenticity.
* **Weighted Risk Scoring:** Calculates a cumulative 0–100% risk score to classify URLs as **Low Risk 🟢**, **Moderate Risk 🟡**, or **High Risk 🔴**.

---

## 🛠️ Tech Stack

* **Language:** Python 3.10+
* **Frontend Web Framework:** Streamlit
* **Domain & Network Libraries:** `tldextract`, `python-whois`, `socket`, `ssl`
* **Parsing & Logic:** `urllib.parse`, `re`

---

## 🚀 Getting Started

### Prerequisites

* Python 3.8 or higher installed on your machine.

### Installation

1. **Clone the repository:**
   git clone [https://github.com/Miertie/Phishing-Domain-Detector.git]
   cd Phishing-Domain-Detector
2. Install dependencies:
   pip install -r requirements.txt
3. Run the Streamlit application:
   python -m streamlit run main.py