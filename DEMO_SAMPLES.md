# 🎯 PhishGuard Demo & Testing Samples

Use this quick-reference guide during presentations, testing, or demonstrations. Simply copy and paste these pre-crafted samples into the **PhishGuard Scanner** (`/dashboard`).

---

## 🌐 1. URL Scan Samples

### A. Clearly Safe URL (Verdict: `SAFE` | Risk Score: `0–15`)
Ideal for demonstrating false-positive avoidance and how the AI explains benign metrics.

```text
https://en.wikipedia.org/wiki/Computer_security
```
* **Alternate Safe URL:**
```text
https://github.com/microsoft/terminal
```
* **Expected Heuristic Findings:** 
  - Standard HTTPS protocol
  - Verified registered domain structure
  - No deceptive subdomains or credential traps
* **AI Explanation Highlight:** Explains that the domain is well-structured, encrypted, and lacks any deceptive tactics or suspicious parameters.

---

### B. Suspicious URL (Verdict: `SUSPICIOUS` | Risk Score: `30–55`)
Demonstrates warning indicators where users should exercise caution.

```text
http://secure-billing-portal.net:8080/account/login
```
* **Alternate Suspicious URL:**
```text
http://update-verification-notice.com/billing
```
* **Expected Heuristic Findings:** 
  - Insecure unencrypted HTTP protocol
  - Non-standard administrative/web port (`:8080`)
  - Target contains credential keywords (`login`, `billing`)
* **AI Explanation Highlight:** AI identifies the combination of unencrypted communication and alternative ports handling sensitive keywords.

---

### C. Severe Phishing URL (Verdict: `PHISHING` | Risk Score: `75–100`)
Demonstrates high-confidence threat detection and aggressive phishing heuristics.

```text
http://192.168.1.100:8080/login?redirect=http://evil-server.com
```
* **Alternate Phishing URL (@ Obfuscation & Raw IP):**
```text
http://support@185.220.101.5/bank-security/login.php
```
* **Expected Heuristic Findings:** 
  - Raw IP address used as hostname instead of a domain (`192.168.1.100`)
  - `@` symbol userinfo destination spoofing
  - Open redirect parameter (`redirect=http://...`)
  - Credential harvesting keywords
* **AI Explanation Highlight:** Categorizes as "Credential Phishing / IP Impersonation" and explicitly warns the user to close the browser without entering credentials.

---

## 📧 2. Email Scan Samples

### A. Clean Benign Email (Verdict: `SAFE` | Risk Score: `0–15`)

**Subject:**
```text
Team sync notes and project timeline update
```

**Body:**
```text
Hi Team,

Thanks for joining today's sprint planning session. I have attached the meeting notes below.

Please take a look at the revised timeline and let me know if you have any questions before our next standup on Thursday.

Best regards,
Alex Carter
Product Lead
```
* **Expected Result:** `SAFE`
* **AI Explanation Highlight:** Notes standard business communication without pressure tactics or credential requests.

---

### B. Suspicious Email (Verdict: `SUSPICIOUS` | Risk Score: `35–55`)

**Subject:**
```text
Action Required: Review pending vendor invoice INV-88219
```

**Body:**
```text
Hello Accounting Team,

Please review the attached invoice INV-88219 for recent IT services rendered last week. 

Our finance team noticed an irregularity with the payment routing information. Please verify your identity and confirm the payment schedule with us by end of day.

Regards,
Billing Support Team
```
* **Expected Result:** `SUSPICIOUS` (Triggers payment references, verification requests, urgency)
* **AI Explanation Highlight:** Explains social engineering indicators surrounding financial manipulation and end-of-day urgency.

---

### C. High-Risk Phishing Email (Verdict: `PHISHING` | Risk Score: `80–100`)

**Subject:**
```text
URGENT: Your account will be suspended within 24 hours!
```

**Body:**
```text
Dear Customer,

We detected unauthorized login attempts to your online banking profile from an unknown device. 

For your protection, your account has been temporarily restricted and will be permanently terminated within 24 hours unless you verify your identity.

Please click the secure link below to confirm your password and update your security credentials immediately:
http://192.168.1.100:8080/login?redirect=http://evil-server.com

Failure to do so will result in immediate loss of account access.

Security Department
Fraud Prevention Unit
```
* **Expected Result:** `PHISHING` (Combines urgent threats, credential demands, account suspension, and an embedded high-risk IP link)
* **AI Explanation Highlight:** Identifies manufactured urgency, authority impersonation, credential harvesting, and warns never to enter account passwords.

---

## 🧪 3. Demonstration Flow Checklist

1. **Start with a Normal URL:** Show that safe URLs scan quickly and receive a green `SAFE` badge. Click **[ AI Security Analysis ]** to show how Gemini explains safe metrics without exaggerating certainty.
2. **Scan the Phishing URL:** Show immediate red `PHISHING` verdict and detailed detector indicators (IP Host, Insecure HTTP, Open Redirect).
3. **Click AI Security Analysis:** Show how Gemini translates technical indicators into Threat Category, Plain-English Explanation, and Actionable Recommendations.
4. **Scan the Phishing Email:** Highlight how PhishGuard extracts the embedded URL, analyzes both the email body text and the link, and aggregates the overall risk score.
5. **Show Scan History & Analytics:** Go to `/history` to filter previous results, and `/analytics` to show how your demonstration scans populated the real-time Threat Distribution chart!

