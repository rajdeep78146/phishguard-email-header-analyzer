# PhishGuard v2.0 - Email Header Analysis Tool

PhishGuard v2.0 is a 3rd-year B.Tech CSE Cyber Security academic project developed to analyze email headers and detect possible phishing or spoofing indicators. It is a defensive web-based tool where users can paste raw email headers or Gmail original message details, and the system extracts important fields such as From, Reply-To, Return-Path, Message-ID, SPF, DKIM, DMARC, and Received hops. Based on these checks, PhishGuard calculates a risk score from 0 to 100 and gives a final verdict as Safe, Suspicious, or Likely Phishing.

---

## Project Objective

The main objective of this project is to make email header analysis simple and understandable for students and users. Phishing emails often hide their real identity using spoofed sender names, suspicious domains, failed authentication checks, and misleading reply addresses. PhishGuard helps detect these warning signs by converting technical email metadata into a simple security report.

---

## Features

- Paste raw email headers or Gmail original message details
- Extracts important email header fields
- Checks SPF, DKIM, and DMARC results
- Detects Reply-To mismatch
- Detects Return-Path mismatch
- Detects missing Message-ID
- Detects missing Authentication-Results header
- Detects suspicious domain extensions such as `.xyz`, `.top`, `.click`, `.link`, `.pw`, and `.loan`
- Detects high number of Received hops
- Detects free email domains pretending to be official accounts
- Generates a risk score from 0 to 100
- Gives final verdict as Safe, Suspicious, or Likely Phishing
- Provides a simple cybersecurity-themed web interface
- Includes optional DNS check for SPF and DMARC records

---

## Tech Stack

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- Flask
- Flask-CORS
- dnspython

### Tools Used
- VS Code
- GitHub
- Vercel

---

## Folder Structure

```text
phishguard/
│
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── public/
    ├── index.html
    ├── style.css
    └── script.js
```

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/rajdeep78146/phishguard-email-header-analyzer.git
```

```bash
cd phishguard-email-header-analyzer
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

If `pip` does not work, use:

```bash
python -m pip install -r requirements.txt
```

### 3. Run Flask Backend

```bash
python app.py
```

The backend will run on:

```text
http://127.0.0.1:5000
```

### 4. Run Frontend

Open `public/index.html` using Live Server in VS Code.

Local frontend usually runs on:

```text
http://127.0.0.1:5500/public/index.html
```

---

## Local and Deployment API Handling

In `script.js`, the project uses API logic that allows it to work both locally and after deployment.

```js
const API_URL =
    window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost"
        ? "http://127.0.0.1:5000/analyze"
        : "/analyze";
```

This means:

- Locally, the frontend connects to Flask backend on port `5000`
- On Vercel, it uses the deployed route `/analyze`

---

## Sample Safe Header

```text
From: Google <noreply-accounts@google.com>
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
Message-ID: <123@google.com>
Return-Path: <noreply-accounts@google.com>
```

Expected result:

```text
Verdict: Safe
Risk Score: Low
```

---

## Sample Unsafe Header

```text
From: University IT Support <support@university-login.xyz>
Reply-To: urgent-helpdesk@gmail.com
Subject: Urgent Account Verification Required
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Return-Path: <bounce@unknown-server.top>
Received: from server1
Received: from server2
Received: from server3
Received: from server4
Received: from server5
Received: from server6
Received: from server7
Received: from server8
```

Expected result:

```text
Verdict: Likely Phishing
Risk Score: High
```

---

## Risk Scoring Logic

| Condition | Score Added |
|---|---:|
| SPF fail or softfail | 30 |
| DKIM fail | 20 |
| DMARC fail | 20 |
| Reply-To mismatch | 25 |
| Return-Path mismatch | 15 |
| Missing Message-ID | 10 |
| Missing Authentication-Results | 15 |
| Suspicious TLD | 15 |
| High Received hops | 15 |
| Free email pretending to be official | 20 |

Final score is limited to 100.

---

## Verdict Logic

| Risk Score | Verdict |
|---|---|
| 0 - 29 | Safe |
| 30 - 69 | Suspicious |
| 70 - 100 | Likely Phishing |

---

## How It Works

1. User pastes an email header into the frontend.
2. JavaScript sends the header to the Flask backend.
3. Flask receives the header through the `/analyze` API route.
4. `analyzer.py` parses the header using Python email parsing functions.
5. The tool extracts important fields like From, Reply-To, Return-Path, and Message-ID.
6. It checks SPF, DKIM, and DMARC results.
7. It applies rule-based phishing detection logic.
8. A risk score and verdict are returned to the frontend.
9. The frontend displays the result to the user.

---

## Deployment

This project is deployed using Vercel.

Deployment flow:

```text
VS Code → GitHub → Vercel
```

Steps:

1. Project was developed locally in VS Code.
2. Code was pushed to GitHub.
3. GitHub repository was imported into Vercel.
4. Vercel deployed the project online.

---

## Limitations

- This tool analyzes email headers only.
- It does not analyze email body content.
- It does not scan attachments.
- It does not block phishing emails automatically.
- DNS lookup depends on internet availability.
- The risk score is based on rule-based logic, not machine learning.

---

## Future Scope

- Add URL scanning from email body
- Add attachment analysis
- Add IP geolocation for sender servers
- Add database to store previous scan reports
- Add machine learning-based phishing detection
- Add downloadable PDF report

---

## Viva Explanation

PhishGuard is a defensive cybersecurity project that helps detect phishing emails by analyzing email headers. It checks authentication results like SPF, DKIM, and DMARC, and also detects mismatches in Reply-To and Return-Path fields. The backend is built using Python Flask, and the frontend is built using HTML, CSS, and JavaScript. The tool assigns risk points for suspicious indicators and gives a final verdict as Safe, Suspicious, or Likely Phishing.

---

## Author

Rajdeep Singh  
B.Tech CSE Cyber Security  
3rd Year Academic Project