"""Observable lexical cues, never proof of fraud or sender identity."""
import ipaddress
import re
from urllib.parse import urlsplit
from .privacy import normalize_sms

DESCRIPTIONS = {
    "URGENCY": "Urgent wording appears",
    "THREAT_OF_BLOCK": "Account restriction wording appears",
    "OTP_REQUEST": "A code sharing request appears",
    "LINK_PRESENT": "Link-like text appears",
    "SHORTENER_LINK": "A known link shortener appears",
    "BANK_IMPERSONATION": "Suspicious bank-related request or warning appears",
    "KYC_IMPERSONATION": "Identity verification wording appears",
    "UPI_COLLECT_LURE": "Payment collection wording appears",
    "DELIVERY_LURE": "Delivery-related wording appears",
    "PRIZE_LURE": "Prize-related wording appears",
    "JOB_LURE": "Job-related wording appears",
    "HINGLISH_CUE": "Romanized Hindi wording appears",
    "IP_HOST_URL": "A numeric network address host appears",
    "PUNYCODE_OR_AT_URL": "Obfuscated host or credential syntax appears",
    "SUSPICIOUS_TLD_URL": "An elevated-risk top-level domain appears",
    "DEEP_SUBDOMAIN_URL": "Deeply nested subdomain structure appears",
    "BRAND_SPOOF_URL": "Brand-like login or verification path wording appears",
    "RISKY_EXTENSION_URL": "Executable or archive download path wording appears",
}

HIGH_RISK_INDICATORS = frozenset({
    "OTP_REQUEST",
    "UPI_COLLECT_LURE",
    "SHORTENER_LINK",
    "THREAT_OF_BLOCK",
    "BANK_IMPERSONATION",
    "KYC_IMPERSONATION",
    "PRIZE_LURE",
    "JOB_LURE",
})
CONTEXTUAL_INDICATORS = frozenset({
    "LINK_PRESENT",
    "URGENCY",
    "DELIVERY_LURE",
    "HINGLISH_CUE",
})

PATTERNS = {
    "URGENCY": r"\b(?:urgent|immediately|right now|last chance|jaldi|turant)\b",
    "THREAT_OF_BLOCK": r"\b(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed|ion)|freeze|frozen)\b",
    "KYC_IMPERSONATION": r"\b(?:kyc|know your customer|identity verification)\b",
    "DELIVERY_LURE": r"\b(?:parcel|delivery|courier|shipment)\b",
    "PRIZE_LURE": r"\b(?:prize|lottery|jackpot|winner|won)\b",
    "JOB_LURE": r"\b(?:job|recruitment|hiring|vacancy|work from home)\b",
    "HINGLISH_CUE": r"\b(?:aapka|aapke|aapki|apna|apne|karo|karein|jaldi|turant|paisa|paise|bhejo|batao|nahi|mat|sunao|karwaya)\b",
}

_OTP_NOUN = (
    r"(?:otp|o\.t\.p\.|one[- ]time\s+(?:password|passcode|code|pin)|"
    r"verification\s+code|security\s+code|login\s+code|auth(?:entication)?\s+code|"
    r"(?:\d+|four|six|eight)[- ]digit\s+(?:otp|code|pin))"
)
_OTP_FWD_VERB = (
    r"(?:share|send|tell|provide|enter|submit|forward|reply(?:\s+with)?|type|confirm|"
    r"give(?:\s+(?:me|us|the|your))?|read(?:\s+out)?(?:\s+aloud)?|speak|dictate|"
    r"bhej(?:o|do|\s+do|\s+dena|\s+dijiye|iye)?|"
    r"bata(?:o|iye|do|\s+do|\s+dein|\s+dena|\s+dijiye)?|"
    r"de\s*do|daal(?:o|ein)?|suna(?:o|\s+do|\s+dein|\s+dijiye)?|"
    r"padh(?:\s*kar)?(?:\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?))?)"
)
# Exclude bare "give" in reverse order and passive past "bheja" so delivery notices never false-trigger.
_OTP_REV_VERB = (
    r"(?:share(?:\s+karo|\s+karein)?|send(?:\s+karo|\s+karein)?|forward(?:\s+karo)?|"
    r"tell|dictate|speak|read(?:\s+out)?(?:\s+aloud)?|"
    r"bol(?:\s*kar)?\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?|do)|"
    r"padh(?:\s*kar)?\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?)|"
    r"bhej(?:o|\s+do|\s+dena|\s+dijiye|iye)?|"
    r"bata(?:o|iye|\s+do|\s+dein|\s+dena)?|suna(?:o|\s+do|\s+dein|\s+dijiye)|de\s*do|dijiye|daal(?:o|ein)?|"
    r"type\s+karo|enter\s+karo)"
)

OTP_FWD_RE = re.compile(rf"\b(?P<verb>{_OTP_FWD_VERB})\b[^.!?;]{{0,45}}?\b{_OTP_NOUN}\b")
OTP_REV_RE = re.compile(rf"\b{_OTP_NOUN}\b[^.!?;]{{0,45}}?\b(?P<verb>{_OTP_REV_VERB})\b")
OTP_READ_ALOUD_GENERIC_CODE_RE = re.compile(
    r"\b(?P<verb>read(?:\s+out)?(?:\s+aloud)?|bol(?:\s*kar)?\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?)|padh(?:\s*kar)?\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?))\b"
    r"[^.!?;]{0,35}?\bcode\b[^.!?;]{0,35}?\b(?:aloud|over\s+(?:the\s+)?(?:phone|call)|on\s+(?:the\s+)?call|suna(?:o|\s+do|\s+dein)?|to\s+(?:me|us|caller|agent))\b"
    r"|\b(?P<verb_aloud>read(?:\s+out)?\s+aloud)\b[^.!?;]{0,25}?\bcode\b"
    r"|\bcode\b[^.!?;]{0,35}?\b(?P<verb2>read(?:\s+out)?\s+aloud|aloud\b[^.!?;]{0,15}\bread|bol(?:\s*kar)?\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?)|padh(?:\s*kar)?\s+(?:bata(?:o|iye|\s+do|\s+dein)?|suna(?:o|\s+do|\s+dein)?))\b"
)
_OTP_ENTRY_ONLY_RE = re.compile(r"^(?:enter(?:\s+karo)?|type(?:\s+karo)?|daal(?:o|ein)?)$")
_LITERAL_OTP_CODE_RE = re.compile(
    r"\b(?:otp|passcode|code|pin)\s*[:#-]?\s*\d{4,8}\b|"
    r"\b\d{4,8}\s+(?:is\s+your\s+|hai\s+)?(?:otp|one[- ]time\s+(?:password|passcode|code))\b"
)
_OTP_SCAM_LURE_RE = re.compile(
    r"\b(?:refund|reverse|cancel|claim|prize|kyc|unblock|reactivate|collect|winner|lottery)\b"
)

_CRED_NOUN = (
    r"(?:atm\s+pin|upi\s+pin|mpin|m-pin|tpin|t-pin|pin|cvv|cvc|pwd|passcode|password|"
    r"card\s+(?:no\.?|number|details)|login\s+(?:id|details|credentials)|credentials|"
    r"pan\s+(?:card|no\.?|number|details)|aadhaar|aadhar)"
)
CRED_FWD_RE = re.compile(
    r"\b(?P<verb>share|send|tell|provide|enter|submit|confirm|verify|update|reply\s+with|"
    rf"read(?:\s+out)?|bhej(?:o|do|\s+do)?|bata(?:o|iye)?|daal(?:o|ein)?|de\s*do)\b[^.!?;]{{0,45}}?\b{_CRED_NOUN}\b"
)
CRED_REV_RE = re.compile(
    rf"\b{_CRED_NOUN}\b[^.!?;]{{0,45}}?\b(?P<verb>share(?:\s+karo|\s+karein)?|send(?:\s+karo)?|"
    r"bhej(?:o|\s+do|\s+dena)?|bata(?:o|iye|\s+do)?|de\s*do|daal(?:o|ein)?|enter\s+karo|submit\s+karo)\b"
)

PRE_NEGATION = re.compile(
    r"\b(?:"
    r"(?:do not|don't|never|not to|no need to|not required to|avoid|refuse to|"
    r"will not|won't|cannot|can't|should not|shouldn't|"
    r"kabhi(?:\s+bhi)?\s+(?:mat|na|nahi)|mat|na|nahi)\s+(?:ever\s+)?(?:to\s+)?|"
    r"(?:never|will\s+never|will\s+not|won't|do\s+not|don't|cannot|can't|not)\s+"
    r"(?:(?:ever|call|phone|sms|text|contact)\s+)?"
    r"(?:(?:to\s+)?(?:ask|asks|asking|request|requests|requesting|tell|tells|require|requires|need|needs)\s+)"
    r"(?:(?:you|customers?|users?|anyone)\s+)?(?:to\s+)?|"
    r"not\s+(?:a\s+)?request\s+(?:to\s+)?"
    r")$"
)
POST_NEGATION = re.compile(
    r"^\s*(?:(?:karo|karein|karna|karni|karne|bharna|daalna|dena)\s+)?"
    r"(?:(?:kabhi(?:\s+bhi)?|bilkul|hargiz)\s+)?"
    r"(?:(?:ki\s+(?:koi\s+)?(?:zaroorat|jarurat|aavashyakta|need)|zaroori|jaruri|aavashyak|required|necessary)(?:\s+bhi)?\s+)?(?:mat|na|nahi)\b|"
    r"^\s*(?:mat|na|nahi)\s+(?:karo|karein|karna|karni|hot[aei]|chahiye|hai)\b"
)

UPI_COLLECT_FWD_RE = re.compile(
    r"\b(?P<verb>approve|accept|confirm|authori[sz]e)\b[^.!?;]{0,40}?\b"
    r"(?:(?:upi|payment|debit)\s+)?(?:collect\s+(?:request|prompt|notification|popup)|upi\s+request|payment\s+request)\b"
    r"|\b(?P<verb2>approve|accept|confirm|authori[sz]e)\b[^.!?;]{0,35}?\b(?:upi|payment)\b[^.!?;]{0,25}?\b(?:collect|request)\b"
)
UPI_COLLECT_REV_RE = re.compile(
    r"\b(?:(?:upi|payment)\s+(?:collect|request)|collect\s+(?:request|prompt|notification|popup))\b"
    r"[^.!?;]{0,40}?\b(?P<verb>approve(?:\s+karo|\s+karein)?|accept(?:\s+karo|\s+karein)?|confirm(?:\s+karo)?|karo|karein)\b"
)

# Banking context alone (e.g., e-statements, credit/debit alerts, routine OTPs) is NOT
# impersonation. BANK_IMPERSONATION requires banking/account context paired with a
# suspicious action, credential solicitation, threat, KYC demand, or deceptive link cue.
BANK_CONTEXT = re.compile(
    r"\b(?:bank|banking|banker|a/c|a\.c\.|acct|"
    r"ac\s+(?:no\.?|number|xx|\*+\d|\d{2,}|credited|debited|bal(?:ance)?|statement|kyc|otp|pin|pwd|holder)|account|"
    r"debit\s+card|credit\s+card|atm\s+card|net\s*banking|mobile\s+banking|"
    r"mpin|m-pin|tpin|t-pin|atm\s+pin|upi\s+pin|"
    r"hdfc|sbi|icici|axis|kotak|pnb|canara|bob)\b"
)

BANK_SUSPICIOUS_PRESSURE = re.compile(
    r"\b(?:reactivat(?:e|ion)|unblock|account\s+(?:on\s+hold|restricted|compromised|locked|will\s+be\s+closed)|"
    r"card\s+(?:blocked|suspended|locked|deactivated|on\s+hold)|"
    r"net\s*banking\s+(?:blocked|suspended|locked|deactivated)|"
    r"verify\s+(?:now|immediately|your\s+(?:account|card|kyc|pan))|"
    r"update\s+(?:your\s+)?(?:kyc|pan|aadhaar|aadhar|bank\s+details|account\s+details)|"
    r"avoid\s+(?:block|blocking|suspension|deactivation|closure)|"
    r"call\s+(?:immediately|urgently|now\s+to\s+(?:unblock|reactivate|verify)))\b"
)

KYC_COMPLETED_RE = re.compile(
    r"\b(?:kyc\b[^.!?;]{0,90}\b(?:completed|verified|updated(?:\s+successfully)?|approved|marked\s+(?:as\s+)?current|stand(?:s)?\s+current|"
    r"up\s+to\s+date|finished\s+(?:processing|verification|review|check|audit)|"
    r"(?:passed|cleared)\s+(?:check|verification|review|validation|audit|inspection|compliance(?:\s+audit)?)|"
    r"recorded\s+as\s+(?:current|complete|updated)|"
    r"(?:poora|poorn|complete|samaapt|safal)\s+ho(?:\s*kar|\s+gay[aei]|\s+chuk[ei])|"
    r"(?:updat(?:e|ed)|verify|verified|approv(?:e|ed))(?:\s+(?:aur|and)\s+(?:approv(?:e|ed)|verify|verified|updat(?:e|ed)))?\s+ho(?:\s*kar|\s+gay[aei]|\s+chuk[ei])|"
    r"current\s+mark\s+ho\s+(?:chuk[ei]|gay[aei]))|"
    r"(?:completed|verified|approved|cleared|passed|finished)\b[^.!?;]{0,65}\bkyc(?:\s+(?:compliance|verification|review|check|audit|inspection|update))?|"
    r"kyc\s+(?:updation|verification)\s+(?:is\s+)?successful)\b"
)

KYC_SCHEDULED_APPT_RE = re.compile(
    r"\b(?:(?:branch|shakh?a)\s+(?:appointment|meeting|slot|visit)|"
    r"(?:appointment|meeting)\b[^.!?;]{0,65}\b(?:branch|shakh?a|scheduled|booked|confirmed|fixed|fix\s+hu[aei]|moved|rescheduled)|"
    r"(?:branch|shakh?a)\b[^.!?;]{0,65}\b(?:appointment|meeting|par\s+jama|counter\s+par\s+jama)|"
    r"kyc(?:\s+(?:desk|update|verification|renewal|check|review|document)){0,3}\s+(?:appointment|meeting|slot|desk\s+review|visit)|"
    r"(?:reserved\s+slot|counter\s+booking|originals?\s+(?:saath\s+laayein|to\s+the\s+counter)|bring\s+original|carry\s+original)|"
    r"(?:scheduled|booked|confirmed|fixed|reserved)\b[^.!?;]{0,80}\b(?:branch|shakh?a|appointment|meeting|counter|desk|slot|kyc)|"
    r"(?:branch|shakh?a|counter|desk|slot|appointment|meeting)\b[^.!?;]{0,65}\b(?:is\s+|has\s+been\s+|was\s+)?(?:scheduled|booked|confirmed|fixed|reserved|book\s+hu[aei]|fix\s+(?:hu[aei]|hai)|tay\s+(?:hai|hu[aei]))|"
    r"visit\s+(?:the\s+|your\s+)?(?:usual\s+|nearest\s+)?(?:branch|shakh?a)[^.!?;]{0,45}?\bkyc\b|"
    r"kyc\b[^.!?;]{0,60}\b(?:nearest\s+branch|at\s+(?:the\s+)?branch|(?:branch|shakh?a)\s+mein|due\s+next\s+month|periodic\s+review|when\s+convenient|fix\s+(?:hu[aei]|hai)|tay\s+hai))\b"
)

_BRANCH_VISIT_CTX_RE = re.compile(
    r"\b(?:(?:branch|shakh?a)\s+(?:appointment|meeting)|visit\s+(?:your\s+|the\s+)?(?:usual\s+|nearest\s+)?(?:branch|shakh?a)|counter\s+#?\d+|at\s+(?:the\s+)?(?:branch|shakh?a)|(?:branch|shakh?a)(?:\s+counter)?\s+par\s+jama)\b"
)
_ACTIVE_KYC_DEMAND_RE = re.compile(
    r"\b(?:update\s+(?:your\s+)?(?:kyc|pan|aadhaar|aadhar)\s+(?:now|immediately|karein|karo)|"
    r"kyc\s+(?:update|verify|submit)\s+(?:now|immediately|karein|karo)|"
    r"(?:verify|submit|send)\s+(?:your\s+)?kyc)\b"
)

USER_REPORTED_BLOCK = re.compile(
    r"\b(?:lost\s+card|stolen\s+card|you\s+reported|per\s+your\s+request|as\s+per\s+your\s+request|"
    r"as\s+requested\s+by\s+you|at\s+your\s+request|upon\s+your\s+request|"
    r"as\s+initiated\s+(?:by|from)\s+your\b|"
    r"(?:(?:(?:as\s+)?per\s+)?your\s+)?(?:manual|self-?(?:initiated|requested)|customer-?(?:initiated|requested)|user-?(?:initiated|requested))\s+"
    r"(?:(?:in-?app|mobile-?app|lost-?card|debit|credit|card)\s+){0,2}"
    r"(?:lock|freeze|block|pause|deactivat(?:ion|e)|disabl(?:e|ement))(?:\s+(?:submission|request|action))?|"
    r"(?:(?:as\s+)?per\s+)?your\s+(?:in-?app\s+|lost-?card\s+|debit\s+)?"
    r"(?:lock|freeze|block|deactivat(?:ion|e)|disabl(?:e|ement))\s+(?:submission|request)|"
    r"you\s+(?:have\s+)?(?:temporarily\s+|permanently\s+)?(?:paused|disabled|turned\s+off|switched\s+off|locked|blocked|froze|frozen)"
    r"(?:\s+(?:your\s+)?(?:debit\s+|credit\s+|atm\s+|swipe\s+)?card|[^.!?;]{0,45}\b(?:card|atm\s+withdrawals?|international\s+usage|debit\s+card|credit\s+card))|"
    r"confirmation\s+that\s+you\s+(?:blocked|locked|froze|frozen)|"
    r"card\b[^.!?;]{0,35}\b(?:blocked|locked|frozen)\s+(?:by\s+you|via\s+(?:the\s+)?(?:official\s+)?(?:app|mobile\s+banking)|in\s+(?:the\s+)?(?:official\s+)?(?:\w+\s+){0,2}app)|"
    r"aapk[ei]\s+(?:request|anurodh|complaint|nirdesh|kehne)\s+(?:par|se|ke\s+anusar|ke\s+baad)|"
    r"aapne\b[^.!?;]{0,55}\b(?:card|debit\s+card|credit\s+card|atm\s+card)\b[^.!?;]{0,35}\b(?:block|lock|freeze|band|disable)\s+(?:kar\s+diya|kiya|karwaya)|"
    r"aapke\s+dwara\b[^.!?;]{0,55}\b(?:(?:card|debit\s+card|credit\s+card)\b[^.!?;]{0,30}\b(?:lock|block|freeze|band)|(?:lock|block|freeze|band)\b)|"
    r"gum\s+hone\s+par|block\s+karwaya)\b"
)

FUTURE_BLOCK_THREAT_RE = re.compile(
    r"\b(?:will\s+be\s+(?:blocked|suspended|deactivated|frozen|closed)|"
    r"block\s+ho\s+jayeg[ai]|band\s+ho\s+jayeg[ai]|"
    r"(?:click|tap|share|send|verify|unblock|reactivate)\b[^.!?;]{0,35}\b(?:unblock|reactivate|block))\b"
)
_PASSIVE_BLOCK_URGENCY_RE = re.compile(
    r"\b(?:blocked|locked|frozen|deactivated|disabled)\s+immediately\b"
)

EDUCATIONAL_ADVISORY_RE = re.compile(
    r"\b(?:fraudsters?|scammers?|tricksters?|swindlers?|impostors?|cheaters?|con\s+artists?|cyber\s*(?:criminals?|thag|crime|fraud)|thags?|apradhi|dhokhebaaz|"
    r"beware\s+of(?:\s+(?:fake|fraud|scam))?|security\s+(?:advisory|bulletin|tip|awareness)|"
    r"(?:digital|cyber)\s+(?:hygiene|suraksha)(?:\s+(?:alert|note|tip|tips|advisory|bulletin|reminder|sandesh|niyam))?|"
    r"cyber\s+(?:note|alert|warning|advisory|safety|tip|bulletin|awareness|suraksha)|"
    r"suraksha\s+(?:sandesh|soochna|soochana|note|niyam|tip|tips|chetavani)|"
    r"(?:khol(?:ne|\s*kar)?|click\s+kar(?:ne|ke|\s*kar)?|tap\s+kar(?:ne|ke)?|verify\s+karne)(?:[^.!?;]{0,40}?\bse\s+bachein)|"
    r"(?:do\s+not|don't|never|avoid|disregard|ignore)\s+(?:(?:click(?:ing)?|tap(?:ping)?|open(?:ing)?)\s+)?"
    r"(?:(?:short|shortened|unknown|unverified|suspicious|unsolicited|random|web|sms|fake|phishing)\s+){0,3}"
    r"(?:urls?|links?|alerts?\s+(?:pushing|demanding|asking))|short\s+urls?\s+demanding|"
    r"fake\s+(?:account\s+)?(?:block|kyc|bank|link|sms|call|message)|"
    r"nakli\s+(?:kyc|bank|e-?kyc|link|block|call|message)|saavdhan|savdhani|jaagrukta|"
    r"(?:bank|bank\s+staff|bank\s+employees?|employees?|staff|representatives?|officers?|adhikari|karmchari|we)\s+"
    r"(?:never|will\s+never|will\s+not|won't|do\s+not|don't|kabhi(?:\s+bhi)?\s+nahi)\s+"
    r"(?:(?:call|phone|contact\s+you|sms|text|message)\s+(?:to\s+)?)?(?:ask|asks|request|maangt[aei]|poocht[aei])|"
    r"(?:bank|bank\s+staff|bank\s+employees?|employees?|staff|officers?|adhikari|karmchari|we)\b[^.!?;]{0,45}"
    r"\bkabhi(?:\s+bhi)?\b[^.!?;]{0,55}\b(?:nahi\s+(?:maangt[aei]|poocht[aei]|pucht[aei]|leta|lete|call\s+kart[aei])|(?:maangt[aei]|poocht[aei])\s+nahi))\b"
)

QUOTED_WARNING_RE = re.compile(
    r"\b(?:if\s+(?:anyone|someone|a\s+caller|any\s+caller)\s+(?:asks?|tells?|says?|claims?|demands?)|"
    r"agar\s+koi\s+(?:bole|kahe|maange|pooche|puche|call\s+kar\s*ke))\b[^.!?;]{0,160}\b"
    r"(?:hang\s+up|disconnect|cut\s+the\s+call|ignore|report|block\s+the\s+number|"
    r"phone\s+kaat\s+(?:dein|do|dena)|call\s+kaat\s+(?:dein|do)|"
    r"vishwas\s+na\s+karein|bharosa\s+na\s+karein|mat\s+(?:batao|batana|do|dena|dein))\b"
)
_DEFENSIVE_URGENCY_RE = re.compile(
    r"\b(?:turant\s+(?:phone|call)\s+kaat|immediately\s+(?:hang\s+up|disconnect|ignore|report))\b"
)

# Bare "open" and "visit" on generic statement/portal links must not imply impersonation.
BANK_LINK_SUSPICIOUS_CUE = re.compile(
    r"\b(?:click|tap|login|log\s+in|sign\s+in|update|verify|unlock|unblock|"
    r"reactivate|submit|confirm|redeem|claim|kyc|pan|aadhaar|aadhar|"
    r"avoid|suspended|blocked)\b"
)
IMPERATIVE_URL_RE = re.compile(
    r"\b(?:click|tap|login|log\s+in|sign\s+in|verify\s+now|update\s+now|submit)\b[^.!?;]*__url__"
)
INFOR_STATEMENT_RE = re.compile(
    r"\b(?:e-?statements?|statements?|passbook|receipt|fee\s+schedule|interest\s+rate)\b"
)

LINK = re.compile(
    r"(?:https?://|www\.)[^\s<>]+|\b[a-z0-9](?:[a-z0-9-]*\.)+(?:com|in|org|net|io|co|me|ly|example|test)\b(?:/[^\s<>]*)?",
    re.I,
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}

_ABBREV_DOT_RE = re.compile(
    r"\b(rs|no|ref|mr|mrs|ms|dr|avl|bal|amt|acct|tx|txn|st|ext|a/c|o\.t\.p)\.(?=\s)"
)


def _normalize_for_cues(text: str) -> str:
    clean = normalize_sms(text).lower()
    clean = re.sub(r"[\u2018\u2019]", "'", clean)
    clean = re.sub(r"[\u2010-\u2015\u2212]", "-", clean)
    return clean


def _mask_links(text: str) -> tuple[str, bool, bool]:
    has_link = False
    has_shortener = False
    parts: list[str] = []
    pos = 0
    for match in LINK.finditer(text):
        has_link = True
        url = match.group()
        is_short = False
        try:
            host = urlsplit(url if "://" in url else "https://" + url).hostname
            if host in SHORTENERS:
                is_short = True
                has_shortener = True
        except ValueError:
            pass
        parts.append(text[pos:match.start()])
        parts.append(" __shorturl__ " if is_short else " __url__ ")
        pos = match.end()
    parts.append(text[pos:])
    return "".join(parts), has_link, has_shortener


def _split_clauses(masked_text: str) -> list[str]:
    placeholder = "\x00"
    protected = re.sub(r"(?<=\d)\.(?=\d)", placeholder, masked_text)
    protected = _ABBREV_DOT_RE.sub(lambda m: m.group(1) + placeholder, protected)
    raw_clauses = re.split(r"[!?;|\n]+|(?<!\d)\.(?=\s|$)", protected)
    return [c.replace(placeholder, ".").strip() for c in raw_clauses if c.strip()]


def _is_negated(clause: str, verb_start: int, verb_end: int) -> bool:
    before = clause[max(0, verb_start - 48):verb_start]
    after = clause[verb_end:min(len(clause), verb_end + 42)]
    return bool(PRE_NEGATION.search(before) or POST_NEGATION.search(after))


def _has_non_negated_group(pattern: re.Pattern, clause: str, group_names: tuple[str, ...] = ("verb",)) -> bool:
    for match in pattern.finditer(clause):
        for name in group_names:
            if name in match.groupdict() and match.group(name) is not None:
                v_start, v_end = match.span(name)
                if not _is_negated(clause, v_start, v_end):
                    return True
    return False


def _is_benign_literal_otp_entry(clause: str, has_url: bool, has_short: bool, has_urgency: bool, has_block: bool) -> bool:
    """Suppress OTP_REQUEST only for benign self-entry instructions naming a literal numeric code."""
    if has_url or has_short or has_urgency or has_block:
        return False
    if _OTP_SCAM_LURE_RE.search(clause) or not _LITERAL_OTP_CODE_RE.search(clause):
        return False
    if _has_non_negated_group(OTP_READ_ALOUD_GENERIC_CODE_RE, clause, ("verb", "verb_aloud", "verb2")):
        return False
    matched_entry = False
    for pattern in (OTP_FWD_RE, OTP_REV_RE):
        for match in pattern.finditer(clause):
            verb = match.group("verb")
            v_start, v_end = match.span("verb")
            if _is_negated(clause, v_start, v_end):
                continue
            if not _OTP_ENTRY_ONLY_RE.fullmatch(verb.strip()):
                return False
            matched_entry = True
    return matched_entry


def _has_non_negated_otp(
    clause: str,
    *,
    has_url: bool = False,
    has_short: bool = False,
    has_urgency: bool = False,
    has_block: bool = False,
) -> bool:
    has_raw = (
        _has_non_negated_group(OTP_FWD_RE, clause)
        or _has_non_negated_group(OTP_REV_RE, clause)
        or _has_non_negated_group(OTP_READ_ALOUD_GENERIC_CODE_RE, clause, ("verb", "verb_aloud", "verb2"))
    )
    if not has_raw:
        return False
    if _is_benign_literal_otp_entry(clause, has_url, has_short, has_urgency, has_block):
        return False
    return True


def _is_quoted_third_party_warning(clause: str, has_url: bool, has_short: bool) -> bool:
    return not has_url and not has_short and bool(QUOTED_WARNING_RE.search(clause))


def _has_non_negated_cred(
    clause: str,
    *,
    has_url: bool = False,
    has_short: bool = False,
    has_urgency: bool = False,
    has_block: bool = False,
) -> bool:
    can_exempt_passcode = (
        not has_url
        and not has_short
        and not has_urgency
        and not has_block
        and not _OTP_SCAM_LURE_RE.search(clause)
        and bool(_LITERAL_OTP_CODE_RE.search(clause))
    )
    for pattern in (CRED_FWD_RE, CRED_REV_RE):
        for match in pattern.finditer(clause):
            verb = match.group("verb")
            v_start, v_end = match.span("verb")
            if _is_negated(clause, v_start, v_end):
                continue
            if can_exempt_passcode and _OTP_ENTRY_ONLY_RE.fullmatch(verb.strip()) and re.search(r"\bpasscode\b", match.group(0)):
                continue
            return True
    return False


def _has_non_negated_upi_collect(clause: str) -> bool:
    return (
        _has_non_negated_group(UPI_COLLECT_FWD_RE, clause, ("verb", "verb2"))
        or _has_non_negated_group(UPI_COLLECT_REV_RE, clause, ("verb",))
    )


def _is_educational_advisory(clause: str, has_short: bool, has_otp: bool, has_cred: bool, has_upi: bool) -> bool:
    if not EDUCATIONAL_ADVISORY_RE.search(clause):
        return False
    if has_short or has_otp or has_cred or has_upi or _ACTIVE_KYC_DEMAND_RE.search(clause):
        return False
    for match in IMPERATIVE_URL_RE.finditer(clause):
        if not PRE_NEGATION.search(clause[max(0, match.start() - 35):match.start()]):
            return False
    return True


def _is_user_initiated_card_block(clause: str, has_url: bool, has_short: bool, has_otp: bool, has_cred: bool) -> bool:
    if has_url or has_short or has_otp or has_cred:
        return False
    if not USER_REPORTED_BLOCK.search(clause):
        return False
    if FUTURE_BLOCK_THREAT_RE.search(clause):
        return False
    return True


def _is_benign_kyc_clause(
    clause: str,
    has_url: bool,
    has_short: bool,
    has_otp: bool,
    has_cred: bool,
    has_upi: bool,
    has_urgency: bool,
    has_block: bool,
) -> bool:
    if has_url or has_short or has_otp or has_cred or has_upi or has_urgency or has_block:
        return False
    return bool(KYC_COMPLETED_RE.search(clause) or KYC_SCHEDULED_APPT_RE.search(clause))


def detect_indicators(text: str) -> tuple[str, ...]:
    clean = _normalize_for_cues(text)
    masked, has_any_link, has_any_shortener = _mask_links(clean)
    has_bank_context = bool(BANK_CONTEXT.search(masked))

    found: set[str] = set()
    if has_any_link:
        found.add("LINK_PRESENT")
    if has_any_shortener:
        found.add("SHORTENER_LINK")

    clauses = _split_clauses(masked)
    has_active_kyc_demand_msg = any(_ACTIVE_KYC_DEMAND_RE.search(c) for c in clauses)
    has_benign_branch_visit_msg = (
        not has_any_link
        and not has_any_shortener
        and not has_active_kyc_demand_msg
        and any(_BRANCH_VISIT_CTX_RE.search(c) for c in clauses)
        and not any(
            COMPILED_PATTERNS["URGENCY"].search(c)
            or COMPILED_PATTERNS["THREAT_OF_BLOCK"].search(c)
            or _has_non_negated_otp(
                c,
                has_url=("__url__" in c),
                has_short=("__shorturl__" in c),
                has_urgency=bool(COMPILED_PATTERNS["URGENCY"].search(c)),
                has_block=bool(COMPILED_PATTERNS["THREAT_OF_BLOCK"].search(c)),
            )
            or _has_non_negated_cred(
                c,
                has_url=("__url__" in c),
                has_short=("__shorturl__" in c),
                has_urgency=bool(COMPILED_PATTERNS["URGENCY"].search(c)),
                has_block=bool(COMPILED_PATTERNS["THREAT_OF_BLOCK"].search(c)),
            )
            or _has_non_negated_upi_collect(c)
            for c in clauses
        )
    )

    has_active_bank_cue = False
    for clause in clauses:
        clause_url = "__url__" in clause
        clause_short = "__shorturl__" in clause
        clause_urgency = bool(COMPILED_PATTERNS["URGENCY"].search(clause))
        clause_block = bool(COMPILED_PATTERNS["THREAT_OF_BLOCK"].search(clause))
        clause_otp = _has_non_negated_otp(
            clause,
            has_url=clause_url,
            has_short=clause_short,
            has_urgency=clause_urgency,
            has_block=clause_block,
        )
        clause_cred = _has_non_negated_cred(
            clause,
            has_url=clause_url,
            has_short=clause_short,
            has_urgency=clause_urgency,
            has_block=clause_block,
        )
        clause_upi = _has_non_negated_upi_collect(clause)
        clause_kyc = bool(COMPILED_PATTERNS["KYC_IMPERSONATION"].search(clause))
        clause_pressure = bool(BANK_SUSPICIOUS_PRESSURE.search(clause))
        clause_suspicious_link = bool((clause_url or clause_short) and (BANK_LINK_SUSPICIOUS_CUE.search(clause) or clause_urgency))

        if clause_url and not clause_short and INFOR_STATEMENT_RE.search(clause):
            if not (clause_otp or clause_cred or clause_upi or clause_urgency or clause_block or BANK_LINK_SUSPICIOUS_CUE.search(clause)):
                clause_suspicious_link = False

        if _is_quoted_third_party_warning(clause, clause_url, clause_short):
            clause_otp = False
            clause_cred = False
            clause_upi = False
            clause_block = False
            clause_kyc = False
            clause_pressure = False
            if clause_urgency and not COMPILED_PATTERNS["URGENCY"].search(_DEFENSIVE_URGENCY_RE.sub("", clause)):
                clause_urgency = False

        if _is_educational_advisory(clause, clause_short, clause_otp, clause_cred, clause_upi):
            clause_block = False
            clause_kyc = False
            clause_pressure = False
            clause_suspicious_link = False

        if _is_user_initiated_card_block(clause, clause_url, clause_short, clause_otp, clause_cred):
            clause_block = False
            clause_pressure = False
            if clause_urgency and not COMPILED_PATTERNS["URGENCY"].search(_PASSIVE_BLOCK_URGENCY_RE.sub("", clause)):
                clause_urgency = False

        if clause_kyc and (
            _is_benign_kyc_clause(
                clause,
                clause_url,
                clause_short,
                clause_otp,
                clause_cred,
                clause_upi,
                clause_urgency,
                clause_block,
            )
            or (has_benign_branch_visit_msg and not _ACTIVE_KYC_DEMAND_RE.search(clause))
        ):
            clause_kyc = False
            clause_pressure = False

        if clause_otp:
            found.add("OTP_REQUEST")
        if clause_urgency:
            found.add("URGENCY")
        if clause_block:
            found.add("THREAT_OF_BLOCK")
        if clause_kyc:
            found.add("KYC_IMPERSONATION")
        if clause_upi:
            found.add("UPI_COLLECT_LURE")
        for simple_name in ("DELIVERY_LURE", "PRIZE_LURE", "JOB_LURE", "HINGLISH_CUE"):
            if COMPILED_PATTERNS[simple_name].search(clause):
                found.add(simple_name)

        if (
            clause_otp
            or clause_cred
            or clause_upi
            or clause_short
            or clause_block
            or clause_kyc
            or clause_pressure
            or clause_suspicious_link
        ):
            has_active_bank_cue = True

    if has_bank_context and has_active_bank_cue:
        found.add("BANK_IMPERSONATION")

    return tuple(name for name in DESCRIPTIONS if name in found)


URL_SHORTENERS = SHORTENERS | {"ow.ly", "rebrand.ly", "tiny.cc"}
SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "click", "icu", "buzz", "cfd", "sbs", "rest",
    "tk", "ml", "ga", "cf", "gq", "vip", "win", "loan", "work", "zip", "mov",
})
RISKY_EXTENSIONS = frozenset({".apk", ".exe", ".scr", ".msi", ".bat", ".cmd", ".vbs", ".jar"})
TRUSTED_MULTI_SLD = frozenset({
    "co.in", "org.in", "gov.in", "nic.in", "ac.in", "net.in", "edu.in", "res.in",
    "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.sg",
})
_CC_SECOND_LEVEL_CATEGORIES = frozenset({"com", "co", "org", "net", "gov", "edu", "ac", "nic", "res", "mil", "sch"})
TRUSTED_INDIAN_GOV_BANK_SUFFIXES = (".gov.in", ".nic.in", ".ac.in", ".res.in", ".edu.in", ".sbi", ".rbi.org.in", ".npci.org.in")
ABUSED_HOSTING_SUFFIXES = (
    ".web.app", ".firebaseapp.com", ".pages.dev", ".vercel.app",
    ".ngrok-free.app", ".workers.dev", ".netlify.app", ".r2.dev",
    ".herokuapp.com", ".blogspot.com", ".github.io",
)
BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "bank.sbi", "sbi.co"),
    "onlinesbi": ("onlinesbi.sbi", "sbi.co.in"),
    "hdfc": ("hdfcbank.com", "hdfc.com"),
    "hdfcbank": ("hdfcbank.com",),
    "icici": ("icicibank.com", "icici.com"),
    "icicibank": ("icicibank.com",),
    "axis": ("axisbank.com", "axisbank.co.in"),
    "axisbank": ("axisbank.com", "axisbank.co.in"),
    "kotak": ("kotak.com", "kotakbank.com"),
    "canarabank": ("canarabank.com", "canarabank.in"),
    "bob": ("bankofbaroda.in", "bobibanking.com"),
    "pnb": ("pnbindia.in", "netpnb.com"),
    "indusind": ("indusind.com",),
    "yesbank": ("yesbank.in",),
    "paytm": ("paytm.com", "paytm.in"),
    "phonepe": ("phonepe.com",),
    "gpay": ("pay.google.com", "google.com"),
    "npci": ("npci.org.in",),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in", "incometaxindiaefiling.gov.in"),
    "parivahan": ("parivahan.gov.in",),
    "echallan": ("parivahan.gov.in", "echallan.parivahan.gov.in"),
    "epfo": ("epfindia.gov.in",),
    "fastag": ("ihmcl.co.in", "npci.org.in"),
    "irctc": ("irctc.co.in",),
    "indiapost": ("indiapost.gov.in",),
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
    "apple": ("apple.com", "icloud.com"),
    "google": ("google.com",),
    "netflix": ("netflix.com",),
    "amazon": ("amazon.com", "amazon.in"),
    "whatsapp": ("whatsapp.com",),
    "github": ("github.com",),
}
_BRAND_LURE_TOKENS = frozenset({"kyc", "ekyc", "netbanking", "webscr"})
_GENERIC_AUTH_TOKENS = frozenset({"login", "signin", "verify", "update", "secure", "account", "unlock", "unblock"})
_INT_OR_HEX_IP_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)$", re.I)


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    stripped = host.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        pass
    if _INT_OR_HEX_IP_RE.match(stripped):
        return True
    parts = stripped.split(".")
    if len(parts) == 4 and all(_INT_OR_HEX_IP_RE.match(p) for p in parts):
        return True
    return False


def parse_url_parts(raw_url: str) -> dict[str, object]:
    """Parse a normalized URL purely locally (no DNS/network) into structured components."""
    text = raw_url.strip()
    has_explicit_scheme = "://" in text
    parsed = urlsplit(text if has_explicit_scheme else "http://" + text)
    scheme = parsed.scheme.lower() if has_explicit_scheme else ""
    netloc = parsed.netloc
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        port = None
    has_at = "@" in netloc or parsed.username is not None or parsed.password is not None
    labels = [lbl for lbl in host.split(".") if lbl] if host else []
    is_ip = _is_ip_host(host)
    if is_ip or len(labels) < 2:
        reg_domain = host
        sub_labels: list[str] = []
        tld = ""
    elif len(labels) >= 3 and (
        ".".join(labels[-2:]) in TRUSTED_MULTI_SLD
        or (len(labels[-1]) == 2 and labels[-2] in _CC_SECOND_LEVEL_CATEGORIES)
    ):
        reg_domain = ".".join(labels[-3:])
        sub_labels = labels[:-3]
        tld = labels[-1]
    else:
        reg_domain = ".".join(labels[-2:])
        sub_labels = labels[:-2]
        tld = labels[-1]
    non_www_subs = [lbl for lbl in sub_labels if lbl != "www"]
    return {
        "scheme": scheme,
        "netloc": netloc,
        "host": host,
        "port": port,
        "has_at": has_at,
        "is_ip": is_ip,
        "labels": labels,
        "reg_domain": reg_domain,
        "sub_labels": sub_labels,
        "non_www_subs": non_www_subs,
        "tld": tld,
        "path": parsed.path or "",
        "query": parsed.query or "",
    }


def has_homoglyph_punycode(labels: list[str]) -> bool:
    """Return True if any punycode label decodes to mixed ASCII + non-ASCII characters (or fails IDNA)."""
    for lbl in labels:
        if not lbl.startswith("xn--"):
            continue
        try:
            decoded = lbl.encode("ascii").decode("idna")
        except UnicodeError:
            return True
        has_ascii_alpha = any("a" <= c.lower() <= "z" for c in decoded)
        has_non_ascii = any(ord(c) > 127 for c in decoded)
        if has_ascii_alpha and has_non_ascii:
            return True
    return False


def detect_url_indicators(url: str) -> tuple[str, ...]:
    """Extract observable structural/lexical cues from a URL without network calls."""
    parts = parse_url_parts(url)
    host = str(parts["host"])
    reg_domain = str(parts["reg_domain"])
    tld = str(parts["tld"])
    path_lower = str(parts["path"]).lower()
    query_lower = str(parts["query"]).lower()
    sub_labels = list(parts["sub_labels"])  # type: ignore[arg-type]
    non_www_subs = list(parts["non_www_subs"])  # type: ignore[arg-type]
    labels = list(parts["labels"])  # type: ignore[arg-type]
    scheme = str(parts["scheme"])
    port = parts["port"]

    found: set[str] = set()
    if parts["is_ip"]:
        found.add("IP_HOST_URL")
    if parts["has_at"] or has_homoglyph_punycode(labels):
        found.add("PUNYCODE_OR_AT_URL")
    if host in URL_SHORTENERS:
        found.add("SHORTENER_LINK")
    if tld in SUSPICIOUS_TLDS:
        found.add("SUSPICIOUS_TLD_URL")
    if len(non_www_subs) >= 3:
        found.add("DEEP_SUBDOMAIN_URL")

    # Check risky executable/archive extension in path or query values.
    if any(path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}&" in query_lower or query_lower.endswith(ext)
           for ext in RISKY_EXTENSIONS):
        found.add("RISKY_EXTENSION_URL")

    host_tokens = set(re.findall(r"[a-z0-9]+", host))
    path_query_tokens = set(re.findall(r"[a-z0-9]+", f"{path_lower} {query_lower}"))
    all_tokens = host_tokens | path_query_tokens
    is_trusted_gov_bank = host.endswith(TRUSTED_INDIAN_GOV_BANK_SUFFIXES)

    brand_spoof = False
    has_nonstd_port = port not in (None, 80, 443)
    has_abused_hosting = host.endswith(ABUSED_HOSTING_SUFFIXES)
    has_risky_host = (
        scheme == "http"
        or tld in SUSPICIOUS_TLDS
        or bool(parts["is_ip"])
        or bool(parts["has_at"])
        or host in URL_SHORTENERS
        or host.count("-") >= 2
        or len(non_www_subs) >= 2
        or has_nonstd_port
        or has_abused_hosting
    )
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if brand in all_tokens and reg_domain not in official_domains and not is_trusted_gov_bank:
            if brand in host_tokens or (all_tokens & (_BRAND_LURE_TOKENS | _GENERIC_AUTH_TOKENS)):
                brand_spoof = True
                break
    if not brand_spoof and (host_tokens & _BRAND_LURE_TOKENS) and not is_trusted_gov_bank and has_risky_host:
        if not any(reg_domain in doms for doms in BRAND_OFFICIAL_DOMAINS.values()):
            brand_spoof = True
    if not brand_spoof and (all_tokens & _GENERIC_AUTH_TOKENS) and not is_trusted_gov_bank:
        if scheme == "http" or "-" in reg_domain or len(non_www_subs) >= 2 or tld in SUSPICIOUS_TLDS or has_nonstd_port or has_abused_hosting:
            if any(tok in host_tokens for tok in _GENERIC_AUTH_TOKENS) or scheme == "http" or tld in SUSPICIOUS_TLDS or has_abused_hosting:
                brand_spoof = True

    if brand_spoof:
        found.add("BRAND_SPOOF_URL")

    return tuple(name for name in DESCRIPTIONS if name in found)
