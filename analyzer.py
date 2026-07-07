import re
import dns.resolver
from email import message_from_string
from email.utils import parseaddr


class HeaderAnalyzer:
    def __init__(self, raw_header):
        # Convert Gmail summary format into normal email header format if needed
        raw_header = self.normalize_header(raw_header)

        # Convert raw header text into Python email object
        self.msg = message_from_string(raw_header)

        self.score = 0
        self.findings = []
        self.extracted_data = {}

    def normalize_header(self, raw_text):
        """
        Converts Gmail summary format into normal email header format.

        Example Gmail summary:
        Message ID    <abc@mail.com>
        SPF: PASS
        DKIM: PASS
        DMARC: PASS

        Converted format:
        Message-ID: <abc@mail.com>
        Authentication-Results: spf=pass; dkim=pass; dmarc=pass
        """

        text = raw_text.strip()
        lines = text.splitlines()
        new_lines = []

        spf_result = ""
        dkim_result = ""
        dmarc_result = ""

        for line in lines:
            clean = line.strip()

            if not clean:
                continue

            lower_line = clean.lower()

            # Convert Gmail "Message ID" to standard "Message-ID:"
            if lower_line.startswith("message id"):
                value = clean[len("Message ID"):].strip()

                if value.startswith(":"):
                    value = value[1:].strip()

                new_lines.append("Message-ID: " + value)

            # Ignore Gmail summary delivery time line
            elif lower_line.startswith("created on:"):
                continue

            # Convert SPF summary into Authentication-Results
            elif lower_line.startswith("spf:"):
                if "softfail" in lower_line:
                    spf_result = "spf=softfail"
                elif "pass" in lower_line:
                    spf_result = "spf=pass"
                elif "fail" in lower_line:
                    spf_result = "spf=fail"

            # Convert DKIM summary into Authentication-Results
            elif lower_line.startswith("dkim:"):
                if "pass" in lower_line:
                    dkim_result = "dkim=pass"
                elif "fail" in lower_line:
                    dkim_result = "dkim=fail"

            # Convert DMARC summary into Authentication-Results
            elif lower_line.startswith("dmarc:"):
                if "pass" in lower_line:
                    dmarc_result = "dmarc=pass"
                elif "fail" in lower_line:
                    dmarc_result = "dmarc=fail"

            else:
                new_lines.append(clean)

        auth_parts = []

        if spf_result:
            auth_parts.append(spf_result)
        if dkim_result:
            auth_parts.append(dkim_result)
        if dmarc_result:
            auth_parts.append(dmarc_result)

        # Add Authentication-Results only if it is not already present
        if auth_parts and "authentication-results:" not in text.lower():
            new_lines.append("Authentication-Results: " + "; ".join(auth_parts))

        return "\n".join(new_lines)

    def get_domain(self, email_addr):
        """Extract domain from email address."""
        if email_addr and "@" in email_addr:
            return email_addr.split("@")[-1].lower()
        return ""

    def check_dns_records(self, domain):
        """
        Simple DNS check:
        - SPF is checked from TXT records
        - DMARC is checked from _dmarc.domain
        """

        results = {
            "spf": "Missing",
            "dmarc": "Missing"
        }

        if not domain:
            return results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        # SPF check
        try:
            txt_records = resolver.resolve(domain, "TXT")

            for record in txt_records:
                if "v=spf1" in str(record):
                    results["spf"] = "Found"
                    break

        except:
            results["spf"] = "Missing"

        # DMARC check
        try:
            resolver.resolve(f"_dmarc.{domain}", "TXT")
            results["dmarc"] = "Found"

        except:
            results["dmarc"] = "Missing"

        return results

    def analyze(self):
        # 1. Extract important header fields
        from_raw = self.msg.get("From", "")
        _, from_email = parseaddr(from_raw)
        from_domain = self.get_domain(from_email)

        reply_to_raw = self.msg.get("Reply-To", "")
        _, reply_to = parseaddr(reply_to_raw)

        return_path_raw = self.msg.get("Return-Path", "")
        _, return_path = parseaddr(return_path_raw)

        msg_id = self.msg.get("Message-ID", "")

        auth_results = self.msg.get("Authentication-Results", "").lower()

        received_headers = self.msg.get_all("Received") or []

        self.extracted_data = {
            "from": from_email,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": msg_id,
            "hops": len(received_headers)
        }

        # 2. SPF, DKIM, DMARC checks
        if "spf=fail" in auth_results or "spf=softfail" in auth_results:
            self.score += 30
            self.findings.append("SPF Failed: Sender IP is not authorized.")

        if "dkim=fail" in auth_results:
            self.score += 20
            self.findings.append("DKIM Failed: Email signature is invalid.")

        if "dmarc=fail" in auth_results:
            self.score += 20
            self.findings.append("DMARC Failed: Domain policy rejected the email.")

        if not auth_results:
            self.score += 15
            self.findings.append("Missing Authentication-Results header.")

        # 3. Reply-To mismatch check
        if reply_to and reply_to.lower() != from_email.lower():
            self.score += 25
            self.findings.append(f"Reply-To Mismatch: Replies go to {reply_to}")

        # 4. Return-Path mismatch check
        return_path_domain = self.get_domain(return_path)

        if return_path and return_path_domain != from_domain:
            self.score += 15
            self.findings.append("Return-Path Mismatch: Bounce-back domain differs from sender domain.")

        # 5. Missing Message-ID check
        if not msg_id:
            self.score += 10
            self.findings.append("Missing Message-ID: Unusual for legitimate email.")

        # 6. High hop count check
        if len(received_headers) > 7:
            self.score += 15
            self.findings.append(f"High Hop Count: Email passed through {len(received_headers)} servers.")

        # 7. Suspicious domain extension check
        suspicious_tlds = [".xyz", ".top", ".click", ".link", ".pw", ".loan"]

        if any(from_domain.endswith(tld) for tld in suspicious_tlds):
            self.score += 15
            self.findings.append(f"Suspicious TLD: Sender domain ends with {from_domain.split('.')[-1]}.")

        # 8. Free email pretending to be official
        free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        official_words = ["admin", "support", "bank", "security", "billing", "service"]

        if from_domain in free_domains:
            if any(word in from_email.lower() for word in official_words):
                self.score += 20
                self.findings.append("Free Email Spoofing: Official-looking name used with free email provider.")

        # 9. Final score limit
        self.score = min(self.score, 100)

        # 10. Verdict
        verdict = "Safe"

        if self.score >= 70:
            verdict = "Likely Phishing"
        elif self.score >= 30:
            verdict = "Suspicious"

        # 11. Optional DNS check
        dns_status = self.check_dns_records(from_domain)

        # 12. Return final result to frontend
        return {
            "data": self.extracted_data,
            "dns": dns_status,
            "score": self.score,
            "verdict": verdict,
            "findings": self.findings
        }