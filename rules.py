"""Rule engine: transparent checks that explain WHY a message looks risky."""
import re


def _asks_secret(t):
    # "Do not share your OTP" is a genuine warning, not a scam.
    if re.search(r"(do not|don't|never)\s+share", t):
        return False
    a = re.search(r"(share|send|tell|give|enter|provide|submit)\b.{0,40}\b(otp|pin|cvv|password)\b", t)
    b = re.search(r"\b(otp|pin|cvv|password)\b.{0,40}\b(share|send|bhejein|cheyandi|cheyyandi)\b", t)
    return bool(a or b)


def _urgency(t):
    return bool(re.search(
        r"\b(immediately|urgent|urgently|right now|last chance|final notice|abhi|ventane)\b"
        r"|within \d+ ?(hours|hour|hrs|minutes)|expires? today|today only"
        r"|will be (blocked|suspended|disconnected|deactivated|cancelled|canceled)", t))


def _link(t):
    return bool(re.search(r"https?://\S+|www\.\S+|\b(bit\.ly|tinyurl\.com)\S*", t))


def _fee(t):
    return bool(re.search(
        r"(registration|processing|security|verification|training|delivery|refundable)\s+(fee|fees|deposit|charge|charges)"
        r"|\bpay\s+(rs|inr|₹)\.?\s?\d|\bfees\s+bhejein", t))


def _prize(t):
    return bool(re.search(
        r"\b(you have won|you won|winner|lottery|lucky draw|jackpot|inaam)\b"
        r"|earn\s+(rs\.?|₹)?\s?\d[\d,]*\s*(daily|per day|every day)"
        r"|guaranteed (job|placement)|placement guaranteed", t))


def _account_threat(t):
    return bool(re.search(
        r"\b(kyc|aadhaar|aadhar|pan card)\b.{0,60}(update|verify|block|deactivat)"
        r"|(update|verify).{0,60}\b(kyc|aadhaar|aadhar|pan)\b"
        r"|(account|sim|upi|card).{0,30}(block|suspend|deactivat)", t))


def _student_fee_scam(t):
    return bool(re.search(
        r"(internship|job|placement|offer letter|scholarship|work from home).{0,120}(fee|deposit|pay\s+(rs|₹)|charge)"
        r"|(fee|deposit|pay\s+(rs|₹)).{0,120}(internship|job|placement|offer letter|scholarship)", t))


# (category, plain-language reason, check function)
RULES = [
    ("OTP / PIN theft", "Asks you to share or enter an OTP, PIN, CVV or password. Real banks never ask for these.", _asks_secret),
    ("Fake urgency", "Pressures you to act immediately or threatens blocking or disconnection.", _urgency),
    ("Suspicious link", "Contains a link. Never tap links in unexpected messages; open the official app or website yourself.", _link),
    ("Advance fee", "Asks you to pay a fee or deposit before you receive anything.", _fee),
    ("Prize / too-good-to-be-true", "Promises a prize, lottery win, guaranteed job or easy daily earnings.", _prize),
    ("KYC / account threat", "Claims your KYC, PAN, Aadhaar, SIM or account will be blocked unless you act.", _account_threat),
    ("Student job / scholarship scam", "Links a job, internship, placement or scholarship to a payment. Genuine ones do not charge fees.", _student_fee_scam),
]


def check_rules(text):
    t = text.lower()
    return [(cat, reason) for cat, reason, fn in RULES if fn(t)]


def risk_level(score):
    if score >= 0.60:
        return "High"
    if score >= 0.35:
        return "Medium"
    return "Low"
