"""Prepare time-aware OpenPhish + real crawled benign URLs + Tranco roots with strict domain-disjoint splits."""
from __future__ import annotations

from collections import defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import random
import shutil
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.indicators import (  # noqa: E402
    ABUSED_HOSTING_SUFFIXES,
    RISKY_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    has_homoglyph_punycode,
    parse_url_parts,
)
from edgeshield.url_detector import normalize_url  # noqa: E402

RAW_DIR = ROOT / "data" / "raw" / "url_feeds"
PROCESSED_DIR = ROOT / "data" / "processed"
SYNTHETIC_DIR = ROOT / "data" / "synthetic"
MANIFEST_PATH = ROOT / "results" / "host" / "url_v1" / "dataset_manifest.json"

OPENPHISH_COMMITS_URL = "https://api.github.com/repos/openphish/public_feed/commits?per_page=60"
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
EALVARADOB_URLS_URL = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json"
HEADERS = {"User-Agent": "EdgeShield-URL-Research/1.0"}

INDIAN_BENIGN_URLS = (
    # Banking & Financial
    ("https://www.onlinesbi.sbi/", "indian_benign"),
    ("https://www.onlinesbi.sbi/sbijava/retail/html/faq.html", "indian_benign"),
    ("https://www.onlinesbi.sbi/documents/cyber-security-tips.pdf", "indian_benign"),
    ("https://sbi.co.in/web/personal-banking/home", "indian_benign"),
    ("https://sbi.co.in/web/customer-care/contact-us", "indian_benign"),
    ("https://www.hdfcbank.com/personal/ways-to-bank/online-banking/net-banking", "indian_benign"),
    ("https://www.hdfcbank.com/personal/useful-links/security", "indian_benign"),
    ("https://www.icicibank.com/personal-banking/insta-banking/internet-banking", "indian_benign"),
    ("https://www.icicibank.com/safe-banking", "indian_benign"),
    ("https://www.axisbank.com/bank-smart/internet-banking/getting-started", "indian_benign"),
    ("https://www.kotak.com/en/personal-banking/ways-to-bank/net-banking.html", "indian_benign"),
    ("https://www.rbi.org.in/Scripts/FAQView.aspx?Id=136", "indian_benign"),
    ("https://www.rbi.org.in/commonman/English/Scripts/AgainstFrauds.aspx", "indian_benign"),
    ("https://www.npci.org.in/what-we-do/upi/product-overview", "indian_benign"),
    ("https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism", "indian_benign"),
    ("https://paytm.com/care/customer-care", "indian_benign"),
    ("https://www.phonepe.com/trust-and-safety/", "indian_benign"),
    # Government & Public Services
    ("https://uidai.gov.in/en/myaadhaar/about-your-aadhaar.html", "indian_benign"),
    ("https://myaadhaar.uidai.gov.in/", "indian_benign"),
    ("https://www.incometax.gov.in/iec/foportal/", "indian_benign"),
    ("https://www.incometax.gov.in/iec/foportal/help/e-filing-faq", "indian_benign"),
    ("https://parivahan.gov.in/parivahan/", "indian_benign"),
    ("https://echallan.parivahan.gov.in/index/accused-challan", "indian_benign"),
    ("https://www.irctc.co.in/nget/train-search", "indian_benign"),
    ("https://www.indiapost.gov.in/_layouts/15/dop.portal.tracking/trackconsignment.aspx", "indian_benign"),
    ("https://www.digilocker.gov.in/about/how-it-works", "indian_benign"),
    ("https://www.mygov.in/campaigns/", "indian_benign"),
    ("https://www.epfindia.gov.in/site_en/For_Employees.php", "indian_benign"),
    ("https://www.cybercrime.gov.in/Webform/Accept.aspx", "indian_benign"),
    ("https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVISORIES", "indian_benign"),
    ("https://www.bharatbillpay.com/consumers/how-it-works", "indian_benign"),
    ("https://www.uidai.gov.in/en/contact-support/have-any-question/1014-faqs.html", "indian_benign"),
)

# Strictly held-out Indian benign domains/URLs (disjoint registrable domains from dev/train)
HOLDOUT_INDIAN_BENIGN_URLS = (
    "https://www.canarabank.com/pages/internet-banking",
    "https://bankofbaroda.in/personal-banking/digital-products/net-banking",
    "https://www.unionbankofindia.co.in/english/cyber-security.aspx",
    "https://www.pnbindia.in/internet-banking.html",
    "https://www.indusind.com/in/en/personal/online-services/netbanking.html",
    "https://www.yesbank.in/digital-banking/internet-banking",
    "https://www.idfcfirstbank.com/personal-banking/ways-to-bank/net-banking",
    "https://www.federalbank.co.in/fednet-internet-banking",
    "https://www.sebi.gov.in/sebiweb/home/HomeAction.do?doListing=yes",
    "https://www.irdai.gov.in/consumer-education",
    "https://www.gst.gov.in/help/returns",
    "https://www.mca.gov.in/content/mca/global/en/home.html",
    "https://www.umang.gov.in/landing/",
    "https://www.passportindia.gov.in/AppOnlineProject/online/faqApplicationForm",
    "https://www.cowin.gov.in/",
    "https://www.nvsp.in/",
    "https://www.ncs.gov.in/Pages/default.aspx",
    "https://www.ugc.gov.in/Notices",
    "https://www.aicte-india.org/bureaus/administration",
    "https://www.iitb.ac.in/en/about-iit-bombay",
    "https://www.iitm.ac.in/academics/study-at-iitm",
    "https://www.isro.gov.in/Mission_Chandrayaan3.html",
    "https://www.drdo.gov.in/drdo/technology-clusters",
    "https://www.nic.in/servicecontents/email/",
    "https://www.bsnl.co.in/opencms/bsnl/BSNL/services/broadband/index.html",
)


def _download_to_file(url: str, dest: Path, *, timeout: int = 20) -> Path:
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_dest = dest.with_suffix(dest.suffix + ".tmp")
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp, tmp_dest.open("wb") as out:
        shutil.copyfileobj(resp, out, length=1024 * 1024)
    tmp_dest.replace(dest)
    return dest


def _fetch_bytes(url: str, dest: Path, *, timeout: int = 20) -> bytes:
    return _download_to_file(url, dest, timeout=timeout).read_bytes()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_clean_crawled_benign(url: str, excluded: set[str]) -> tuple[bool, str]:
    try:
        clean = normalize_url(url)
    except ValueError:
        return False, ""
    parts = parse_url_parts(clean)
    host = str(parts["host"])
    reg_dom = str(parts["reg_domain"])
    tld = str(parts["tld"])
    path_lower = str(parts["path"]).lower()
    query_lower = str(parts["query"]).lower()
    if not host or "." not in host or not reg_dom or not tld:
        return False, ""
    if host.endswith(".arpa") or parts["is_ip"] or parts["has_at"]:
        return False, ""
    if has_homoglyph_punycode(list(parts["labels"])):  # type: ignore[arg-type]
        return False, ""
    if host in URL_SHORTENERS or host.endswith(ABUSED_HOSTING_SUFFIXES) or tld in SUSPICIOUS_TLDS:
        return False, ""
    if len(str(parts["path"]).strip("/")) == 0 and not query_lower:
        return False, ""
    if any(
        path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}&" in query_lower or query_lower.endswith(ext)
        for ext in RISKY_EXTENSIONS
    ):
        return False, ""
    pq = f"{path_lower}?{query_lower}" if query_lower else path_lower
    if any(marker in pq for marker in ("http://", "https://", "http%3a", "https%3a")):
        return False, ""
    if host in excluded or reg_dom in excluded:
        return False, ""
    return True, reg_dom


def _download_ealvaradob_benign(n_urls: int = 5400, excluded_domains: set[str] | None = None) -> list[dict]:
    excluded = excluded_domains or set()
    raw_path = _download_to_file(EALVARADOB_URLS_URL, RAW_DIR / "ealvaradob_urls.json", timeout=120)
    data = json.loads(raw_path.read_text(encoding="utf-8", errors="ignore"))
    rng = random.Random(20261124)

    https_by_dom: dict[str, str] = {}
    http_by_dom: dict[str, str] = {}
    bare_by_dom: dict[str, str] = {}

    for item in data:
        if int(item.get("label", -1)) != 0:
            continue
        raw_u = str(item.get("text", "")).strip()
        if not raw_u:
            continue
        lower = raw_u.lower()
        if lower.startswith("https://"):
            ok, reg_dom = _is_clean_crawled_benign(raw_u, excluded)
            if ok and reg_dom not in https_by_dom:
                https_by_dom[reg_dom] = raw_u
        elif lower.startswith("http://"):
            ok, reg_dom = _is_clean_crawled_benign(raw_u, excluded)
            if ok and reg_dom not in http_by_dom:
                http_by_dom[reg_dom] = raw_u
        elif "://" not in raw_u and "/" in raw_u:
            cand = f"https://{raw_u}"
            ok, reg_dom = _is_clean_crawled_benign(cand, excluded)
            if ok and reg_dom not in bare_by_dom:
                bare_by_dom[reg_dom] = cand

    https_items = list(https_by_dom.items())
    http_items = list(http_by_dom.items())
    bare_items = list(bare_by_dom.items())
    rng.shuffle(https_items)
    rng.shuffle(http_items)
    rng.shuffle(bare_items)

    https_target = int(n_urls * 0.90)
    used_reg: set[str] = set()
    records: list[dict] = []

    for reg_dom, url in https_items:
        if len(records) >= https_target:
            break
        used_reg.add(reg_dom)
        records.append({"url": url, "label": 0, "source": "ealvaradob_benign_crawled", "reg_domain": reg_dom})

    if len(records) < https_target:
        for reg_dom, url in bare_items:
            if len(records) >= https_target:
                break
            if reg_dom in used_reg:
                continue
            used_reg.add(reg_dom)
            records.append({"url": url, "label": 0, "source": "ealvaradob_benign_crawled", "reg_domain": reg_dom})

    for reg_dom, url in http_items:
        if len(records) >= n_urls:
            break
        if reg_dom in used_reg:
            continue
        used_reg.add(reg_dom)
        records.append({"url": url, "label": 0, "source": "ealvaradob_benign_crawled", "reg_domain": reg_dom})

    rng.shuffle(records)
    return records


def _download_openphish_snapshots() -> list[dict]:
    commits_path = RAW_DIR / "openphish_commits.json"
    commits = json.loads(_fetch_bytes(OPENPHISH_COMMITS_URL, commits_path).decode("utf-8"))
    # Select ~30 chronological snapshots (oldest -> newest) across the fetched commits.
    selected = list(reversed(commits[::2][:30]))
    earliest_seen: dict[str, tuple[str, str]] = {}
    for c in selected:
        sha = c["sha"]
        ts = c["commit"]["committer"]["date"]
        raw_url = f"https://raw.githubusercontent.com/openphish/public_feed/{sha}/feed.txt"
        snap_path = RAW_DIR / "openphish" / f"{sha[:10]}.txt"
        text = _fetch_bytes(raw_url, snap_path).decode("utf-8", errors="ignore")
        for line in text.splitlines():
            url = line.strip()
            if not url.startswith(("http://", "https://")) or len(url) > 2048:
                continue
            if url not in earliest_seen or ts < earliest_seen[url][0]:
                earliest_seen[url] = (ts, sha[:10])
    records = []
    for url, (ts, snap) in sorted(earliest_seen.items(), key=lambda kv: (kv[1][0], kv[0])):
        parts = parse_url_parts(url)
        if not parts["host"]:
            continue
        records.append({
            "url": url,
            "label": 1,
            "source": "openphish_public_feed",
            "first_seen_utc": ts,
            "snapshot": snap,
            "reg_domain": parts["reg_domain"],
        })
    return records


def _download_tranco_benign(n_domains: int = 2400, excluded_domains: set[str] | None = None) -> list[dict]:
    excluded = excluded_domains or set()
    zip_path = RAW_DIR / "tranco_top1m.zip"
    raw_zip = _fetch_bytes(TRANCO_ZIP_URL, zip_path)
    rng = random.Random(20261124)
    domains: list[tuple[int, str]] = []
    seen_reg: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as stream:
            reader = csv.reader(io.TextIOWrapper(stream, encoding="utf-8"))
            for row in reader:
                if len(row) < 2:
                    continue
                rank = int(row[0])
                dom = row[1].strip().lower()
                if dom.endswith(".arpa") or f".{dom}".endswith(ABUSED_HOSTING_SUFFIXES):
                    continue
                parts = parse_url_parts(f"https://{dom}/")
                reg_dom = str(parts["reg_domain"])
                if str(parts["tld"]) in SUSPICIOUS_TLDS:
                    continue
                if dom in excluded or reg_dom in excluded or reg_dom in seen_reg:
                    continue
                # Sample across top 1..100,000 ranks for diversity.
                if rank <= 100000 and (rank <= 1200 or rank % 13 == 0):
                    seen_reg.add(reg_dom)
                    domains.append((rank, dom))
                if len(domains) >= n_domains:
                    break

    records = []
    for idx, (rank, dom) in enumerate(domains):
        host = f"www.{dom}" if (idx % 5 < 3 and dom.count(".") == 1) else dom
        scheme = "https" if idx % 10 != 0 else "http"
        url = f"{scheme}://{host}/"
        parts = parse_url_parts(url)
        records.append({
            "url": url,
            "label": 0,
            "source": "tranco_top100k_roots",
            "rank": rank,
            "reg_domain": parts["reg_domain"],
        })
    rng.shuffle(records)
    return records


def _build_indian_synthetic_datasets() -> tuple[list[dict], list[dict]]:
    dev_rows = []
    for url, src in INDIAN_BENIGN_URLS:
        dev_rows.append({"url": url, "label": 0, "source": src, "reg_domain": parse_url_parts(url)["reg_domain"]})

    # Synthetic Indian phishing dev patterns (disjoint domains from holdout!)
    dev_phish = [
        "http://sbi-ekyc-verify.xyz/netbanking/login.php",
        "http://hdfc-pan-update.top/kyc/verify?id=4821",
        "https://icici.netbanking-alert.click/auth/otp",
        "http://paytm-kyc-bonus.icu/claim/reward.php",
        "http://phonepe.refund-claim.buzz/upi/collect",
        "http://aadhaar-uidai-update.cfd/portal/ekyc",
        "http://incometax-refund-portal.sbs/verify-pan",
        "http://parivahan-echallan-pay.xyz/challan/download/eChallan.apk",
        "http://indiapost-parcel-duty.work/track/rebook?id=9912",
        "http://irctc-ticket-refund.top/upi/verify",
        "http://198.51.100.77/sbi/kyc-update.html",
        "http://192.0.2.55:8080/hdfc-reward/app-release.apk",
        "https://xn--sbi-onlne-05a.example/login",
        "https://onlinesbi.sbi@evil-portal.xyz/login",
        "http://kotak.account.block.verify.rest/unlock",
        "http://axisbank-reward-points.vip/redeem",
        "http://npci-upi-reversal.win/collect/approve",
        "http://electricity-cutoff-bill.click/paynow",
        "http://bit.ly/sbi-kyc-urgent-2026",
        "http://tinyurl.com/hdfc-pan-unblock",
        "http://goo.gl/sbi-pan-kyc-alert",
        "http://ow.ly/hdfc-upi-refund-claim",
        "https://verify.login.kyc.cedarbank-alert.xyz/session",
        "http://microsoft-365-auth.loan/signin",
        "http://paypal-account-limited.work/webscr/cmd=_login",
        "http://whatsapp-web-verify.top/code",
        "https://cedar-netbanking-login.web.app/verify",
        "https://maple-kyc-portal.firebaseapp.com/auth",
        "https://xn--cedarbnk-05a.example/auth",
        "https://cedarbank.example@evil-login.top/verify",
        "http://on1inesbi-retail.example/login",
        "http://hdfcbnak-alert.example/kyc",
        "http://paypa1-resolution.example/signin",
        "http://rnicrosoft-verify.example/oauth",
        "http://g00gle-security-check.example/auth",
        "http://icic1bank-unblock.example/otp",
        "http://parivhan-fine.example/pay",
        "http://paytrn-wallet.example/claim",
        "http://coinbese-wallet.example/auth",
        "http://arnazon-order-hold.example/signin",
    ]
    for url in dev_phish:
        dev_rows.append({"url": url, "label": 1, "source": "indian_phish_dev", "reg_domain": parse_url_parts(url)["reg_domain"]})

    # Strictly unseen 200-URL holdout (100 benign + 100 phishing, zero domain overlap with dev/train)
    holdout_rows = []
    for url in HOLDOUT_INDIAN_BENIGN_URLS:
        holdout_rows.append({"url": url, "label": 0, "source": "indian_benign_holdout", "subset": "indian", "reg_domain": parse_url_parts(url)["reg_domain"]})

    global_benign_holdout_domains = [
        ("github.com", ("/login", "/features/security", "/about/careers")),
        ("docs.python.org", ("/3/library/urllib.parse.html", "/3/tutorial/index.html", "/3/installing/index.html")),
        ("developer.mozilla.org", ("/en-US/docs/Web/Security", "/en-US/docs/Web/HTTP", "/en-US/docs/Learn")),
        ("en.wikipedia.org", ("/wiki/Phishing", "/wiki/Transport_Layer_Security", "/wiki/Hypertext_Transfer_Protocol")),
        ("stackoverflow.com", ("/questions/1000/python-url-parsing", "/tags/python/info", "/help/how-to-ask")),
        ("arxiv.org", ("/abs/2401.00001", "/list/cs.CR/recent", "/help/submit")),
        ("pypi.org", ("/project/scikit-learn/", "/project/numpy/", "/help/")),
        ("scikit-learn.org", ("/stable/modules/linear_model.html", "/stable/user_guide.html", "/stable/install.html")),
        ("www.raspberrypi.com", ("/documentation/computers/raspberry-pi.html", "/products/raspberry-pi-5/", "/news/")),
        ("www.debian.org", ("/releases/trixie/", "/security/", "/doc/manuals/debian-reference/")),
        ("huggingface.co", ("/meta-llama", "/docs/transformers/index", "/models")),
        ("pytorch.org", ("/executorch/stable/index.html", "/get-started/locally/", "/docs/stable/index.html")),
        ("www.cloudflare.com", ("/learning/security/what-is-phishing/", "/learning/dns/what-is-dns/", "/products/")),
        ("owasp.org", ("/www-community/attacks/Phishing", "/www-project-top-ten/", "/about/")),
        ("www.nist.gov", ("/cyberframework", "/publications", "/topics/cybersecurity")),
        ("www.w3.org", ("/TR/url/", "/standards/webdesign/", "/Consortium/")),
        ("www.openssl.org", ("/docs/", "/news/vulnerabilities.html", "/source/")),
        ("kernel.org", ("/doc/html/latest/", "/category/about.html", "/releases.json")),
        ("www.bbc.com", ("/news/technology", "/news/world", "/weather")),
        ("www.reuters.com", ("/technology/", "/business/finance/", "/world/")),
        ("www.nytimes.com", ("/section/technology", "/section/business", "/help/")),
        ("www.ieee.org", ("/publications/index.html", "/conferences/index.html", "/about/index.html")),
        ("acm.org", ("/publications/digital-library", "/education", "/about-acm")),
        ("mit.edu", ("/research/", "/education/", "/admissions-aid/")),
        ("stanford.edu", ("/academics/", "/research/", "/about/")),
    ]
    for dom, paths in global_benign_holdout_domains:
        for p_item in paths:
            url = f"https://{dom}{p_item}"
            holdout_rows.append({"url": url, "label": 0, "source": "global_benign_holdout", "subset": "global", "reg_domain": parse_url_parts(url)["reg_domain"]})

    # 50 Indian phishing + 50 Global phishing (all strictly unseen synthetic domains)
    indian_phish_holdout = [
        f"http://canara-kyc-reactivate-{i}.xyz/netbanking/verify.php" for i in range(1, 9)
    ] + [
        f"http://bob-ekyc-pan-link-{i}.top/login?otp=required" for i in range(1, 9)
    ] + [
        f"https://pnb.account.unblock.session{i}.click/kyc" for i in range(1, 9)
    ] + [
        f"http://parivahan-challan-app-{i}.icu/download/challan{i}.apk" for i in range(1, 9)
    ] + [
        f"http://203.0.113.{10 + i}:8080/upi/refund-collect-{i}.php" for i in range(1, 7)
    ] + [
        "http://is.gd/canara-kyc-urgent-check",
        "http://rb.gy/pnb-account-freeze-now",
        "http://rebrand.ly/epfo-kyc-claim-2026",
        "http://cutt.ly/aadhaar-pan-link-fine",
        "https://onlinesbi.sbi@unverified-kyc-portal.buzz/auth",
        "https://paytm.com@upi-claim-bonus.cfd/pay",
        "http://xn--hdfc-bnk-verify-12a.example/login",
        "http://xn--icici-kyc-update-99b.example/netbanking",
        "http://gst-penalty-notice-pay.work/portal/login.exe",
        "http://bharatbill-power-disconnect.vip/pay-now",
        "http://indiapost-customs-clearance.loan/track?parcel=IN99",
        "http://sebi-ipo-allotment-bonus.sbs/claim",
    ]
    for url in indian_phish_holdout:
        holdout_rows.append({"url": url, "label": 1, "source": "indian_phish_holdout", "subset": "indian", "reg_domain": parse_url_parts(url)["reg_domain"]})

    global_phish_holdout = [
        f"http://microsoft-365-reauth-{i}.cfd/oauth/login.php" for i in range(1, 11)
    ] + [
        f"http://paypal-billing-restore-{i}.buzz/webscr/verify" for i in range(1, 11)
    ] + [
        f"https://apple.id.locked.verify{i}.click/signin" for i in range(1, 11)
    ] + [
        f"http://amazon-prime-hold-{i}.top/ap/signin?ref=alert" for i in range(1, 11)
    ] + [
        f"http://198.18.0.{20 + i}/secure/setup-client-{i}.exe" for i in range(1, 6)
    ] + [
        f"https://login.verify.netflix-billing-update{i}.rest/account" for i in range(1, 6)
    ]
    for url in global_phish_holdout:
        holdout_rows.append({"url": url, "label": 1, "source": "global_phish_holdout", "subset": "global", "reg_domain": parse_url_parts(url)["reg_domain"]})

    assert len([r for r in holdout_rows if r["label"] == 0]) == 100
    assert len([r for r in holdout_rows if r["label"] == 1]) == 100
    return dev_rows, holdout_rows


def _write_jsonl(path: Path, rows: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(r, ensure_ascii=True) for r in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return _sha256_file(path)


def main() -> None:
    openphish = _download_openphish_snapshots()
    dev_rows, holdout_rows = _build_indian_synthetic_datasets()
    holdout_domains = {r["reg_domain"] for r in holdout_rows}
    openphish = [r for r in openphish if r["reg_domain"] not in holdout_domains]

    # Strict time-aware phishing split: earliest ~75% timestamps -> dev/train/cal/val;
    # latest ~25% timestamps (with zero domain overlap with earlier splits) -> test_temporal!
    n_phish = len(openphish)
    cut_idx = int(n_phish * 0.75)
    cutoff_ts = openphish[cut_idx]["first_seen_utc"]
    earlier_phish = [r for r in openphish if r["first_seen_utc"] < cutoff_ts]
    earlier_phish_domains = {r["reg_domain"] for r in earlier_phish}
    future_phish = [
        r for r in openphish
        if r["first_seen_utc"] >= cutoff_ts and r["reg_domain"] not in earlier_phish_domains
    ]

    # Domain-grouped split of earlier_phish into train (70%), cal (15%), val (15%)
    by_dom: dict[str, list[dict]] = defaultdict(list)
    for r in earlier_phish:
        by_dom[r["reg_domain"]].append(r)
    dom_list = sorted(by_dom.keys())
    rng = random.Random(20261124)
    rng.shuffle(dom_list)
    n_dom = len(dom_list)
    n_tr = int(n_dom * 0.70)
    n_ca = int(n_dom * 0.85)
    phish_train = [
        r
        for d in dom_list[:n_tr]
        for r in sorted(by_dom[d], key=lambda row: (row["first_seen_utc"], row["url"]))[:50]
    ]
    phish_cal = [r for d in dom_list[n_tr:n_ca] for r in by_dom[d]]
    phish_val = [r for d in dom_list[n_ca:] for r in by_dom[d]]

    # Real crawled benign full URLs + Tranco top-100k roots (strictly excluding holdout, dev, shorteners, and OpenPhish domains)
    all_phish_domains = {r["reg_domain"] for r in openphish}
    dev_domains = {r["reg_domain"] for r in dev_rows}
    base_excluded = holdout_domains | all_phish_domains | dev_domains | URL_SHORTENERS
    ealvaradob_benign = _download_ealvaradob_benign(n_urls=5400, excluded_domains=base_excluded)
    ealvaradob_domains = {r["reg_domain"] for r in ealvaradob_benign}
    tranco_benign = _download_tranco_benign(n_domains=2400, excluded_domains=base_excluded | ealvaradob_domains)
    benign_all = ealvaradob_benign + tranco_benign
    assert len({r["reg_domain"] for r in benign_all}) == len(benign_all), "Duplicate benign registrable domain!"
    rng.shuffle(benign_all)

    n_ben = len(benign_all)
    b_tr = int(n_ben * 0.55)
    b_ca = int(n_ben * 0.70)
    b_va = int(n_ben * 0.82)
    ben_train = benign_all[:b_tr]
    ben_cal = benign_all[b_tr:b_ca]
    ben_val = benign_all[b_ca:b_va]
    ben_test = benign_all[b_va:]

    train_rows = phish_train + ben_train + dev_rows
    cal_rows = phish_cal + ben_cal
    val_rows = phish_val + ben_val
    test_temporal_rows = future_phish + ben_test

    # Assert strict domain disjointness between train/cal/val vs test_temporal and url_holdout
    dev_all_domains = {r["reg_domain"] for r in train_rows + cal_rows + val_rows}
    test_domains = {r["reg_domain"] for r in test_temporal_rows}
    assert not (dev_all_domains & test_domains), "Domain overlap between dev and test_temporal!"
    assert not (dev_all_domains & holdout_domains), "Domain overlap between dev and url_holdout!"
    assert not (test_domains & holdout_domains), "Domain overlap between test_temporal and url_holdout!"

    hashes = {
        "data/synthetic/url_indian_dev.jsonl": _write_jsonl(SYNTHETIC_DIR / "url_indian_dev.jsonl", dev_rows),
        "data/synthetic/url_holdout.jsonl": _write_jsonl(SYNTHETIC_DIR / "url_holdout.jsonl", holdout_rows),
        "data/processed/url_train.jsonl": _write_jsonl(PROCESSED_DIR / "url_train.jsonl", train_rows),
        "data/processed/url_calibration.jsonl": _write_jsonl(PROCESSED_DIR / "url_calibration.jsonl", cal_rows),
        "data/processed/url_validation.jsonl": _write_jsonl(PROCESSED_DIR / "url_validation.jsonl", val_rows),
        "data/processed/url_test_temporal.jsonl": _write_jsonl(PROCESSED_DIR / "url_test_temporal.jsonl", test_temporal_rows),
    }

    manifest = {
        "created_at_utc": "2026-11-24T08:35:00Z",
        "sources": {
            "openphish": "https://github.com/openphish/public_feed (30 timestamped snapshots)",
            "ealvaradob_phishing_dataset_urls_json": "https://huggingface.co/datasets/ealvaradob/phishing-dataset (Apache-2.0 real crawled benign full URLs, label=0)",
            "tranco_top100k_roots": "https://tranco-list.eu/top-1m.csv.zip (real root URLs only, zero fabricated paths)",
            "indian_synthetic": "Curated Indian banking/gov benign + Indian KYC/UPI/APK/typosquat synthetic phishing patterns",
        },
        "time_cutoff_utc": cutoff_ts,
        "counts": {
            "train": {"total": len(train_rows), "phish": sum(r["label"] for r in train_rows), "benign": len(train_rows) - sum(r["label"] for r in train_rows)},
            "calibration": {"total": len(cal_rows), "phish": sum(r["label"] for r in cal_rows), "benign": len(cal_rows) - sum(r["label"] for r in cal_rows)},
            "validation": {"total": len(val_rows), "phish": sum(r["label"] for r in val_rows), "benign": len(val_rows) - sum(r["label"] for r in val_rows)},
            "test_temporal": {"total": len(test_temporal_rows), "phish": sum(r["label"] for r in test_temporal_rows), "benign": len(test_temporal_rows) - sum(r["label"] for r in test_temporal_rows)},
            "url_holdout": {"total": len(holdout_rows), "phish": sum(r["label"] for r in holdout_rows), "benign": len(holdout_rows) - sum(r["label"] for r in holdout_rows)},
        },
        "disjoint_domain_checks": {
            "dev_vs_test_temporal_overlap": 0,
            "dev_vs_url_holdout_overlap": 0,
            "test_temporal_vs_url_holdout_overlap": 0,
        },
        "sha256": hashes,
    }
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
