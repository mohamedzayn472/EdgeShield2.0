"""Create strictly family-separated V7 synthetic development and fresh unseen V7 holdout datasets.

Preserves all V1-V6 datasets untouched. Enforces zero family overlap, zero exact text overlap,
entity firewalls across dev/V4/V5/V6/V7 brands, and zero cross-partition char 3-5-gram
near-duplicates (>= 0.85 cosine similarity) across V7 dev splits, V7 holdout, V6 holdout,
V5 holdout, V4 holdout, V3 holdout, V2 holdout, indian_sms, UCI processed splits, and
reproduced failure strings.
"""
from __future__ import annotations

import json
from pathlib import Path
from edgeshield.datasets import canonical, check_leakage, digest, group_near_duplicates, read_jsonl, write_jsonl
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]

REPRODUCED_BLACKLIST_TEXTS = [
    "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Bank staff will never ask for your OTP, password, or UPI PIN.",
    "HDFC Bank Alert: Never share your OTP, ATM PIN, CVV, or password with anyone. Bank employees never call to ask for KYC or card details.",
    "Bank Suraksha Soochna: Fraudsters nakli account block ya KYC update link bhejte hain. Bank staff kabhi bhi aapka OTP, password ya UPI PIN nahi maangta.",
    "Cedar Bank: Confirmation that you blocked your debit card XX1234 in the official Cedar Bank app. Call 1800-000-0000 if you did not initiate this.",
    "Aapne official app mein apna debit card XX4512 block kar diya hai. Agar aapne yeh nahi kiya to 1800-000-0000 par call karein.",
    "Cedar Bank: Reminder that your routine KYC update appointment at the Main Street branch is scheduled for 25-Nov-26 at 11:00 AM.",
    "Aapki regular KYC update ke liye MG Road branch mein appointment 25-Nov ko 11 AM baje scheduled hai.",
    "Cedar Bank: Your KYC verification at the branch has been completed successfully.",
    "Cedar Bank: Your October 2026 e-statement for A/c XX1234 is ready. View it at https://mybank.example/statement.",
    "Cedar Bank: Your monthly e-statement for A/c XX1234 is available. Open https://portal.cedarbank.example/doc/oct26 to download.",
    "Hi Mom, my phone broke and I am texting from a new number. Please transfer Rs. 4500 urgently via UPI right now, dont call this number as mic is damaged.",
    "Hi Mom, my phone broke and I am texting from a new number. Please transfer Rs. 4500 urgently via UPI right now, do not call this number as mic is damaged.",
    "Papa mera phone toot gaya hai, yeh mera naya number hai. Please turant 5000 rs is UPI par bhej do, abhi call mat karna mic kharab hai.",
    "Sir aapke card par 4999 ka galat charge laga hai, charge reverse karne ke liye phone par aaya one-time code abhi bol kar batao.",
    "Charge reverse karne ke liye aapke number par jo one-time code aaya hai woh padh kar bata do.",
    "123456 is your OTP for transaction of INR 499.00 on Cedar Bank Card XX1234. Never share your OTP with anyone. Valid for 10 mins.",
    "Cedar Bank Alert: Share your 6-digit OTP immediately to cancel an unauthorized debit of INR 4,999.00.",
    "Never share your OTP with strangers. However, send your OTP now to confirm your refund.",
    "Your failed UPI payment of Rs 850.00 has been reversed and credited back to your A/c XX1234.",
    "Approve this collect request of Rs 850 to receive your failed payment refund immediately.",
]


def _build_v7_development_additions() -> list[dict]:
    """Add family-separated EN/HI dev data targeting V6 FP shapes & unseen scam counters."""
    specs = [
        # --- 1. Benign EN self-entry passcode & verification OTP notices ---
        ("train", "english", 0, "v7_tr_en_passcode_self", [
            "Harbor Bank verification: Key in one-time code 518204 inside our official app portal to register your water utility payee.",
            "Meridian Trust check: Use verification passcode 740193 directly within netbanking preferences to save beneficiary account.",
            "Solstice Card screen: Enter security code 609312 inside your mobile application to enable autopay scheduling.",
            "Evergreen Pay note: Populate temporary passcode 284751 strictly on our official login page; employees never ring for digits.",
            "Oakwood Coop alert: Input single-use OTP 936401 within your personal banking dashboard to whitelist power biller.",
            "Crestline Finance notice: Confirm standing transfer payee using app verification token 415829 inside your logged-in screen.",
            "Banyan Coop portal: Supply 6-digit passcode 852910 solely inside the web session you opened; ignore callers requesting codes.",
            "Pinnacle Bank settings: Type authorization code 193746 directly in our app screen to verify recurring transit pass.",
        ]),
        ("calibration", "english", 0, "v7_cal_en_passcode_self", [
            "Cedar Bank verification: Enter single-use passcode 647182 inside your official app portal to confirm broadband biller setup.",
            "Horizon Rail Wallet: Input temporary OTP 309541 strictly on the app checkout screen; agents never request passcodes.",
        ]),
        ("validation", "english", 0, "v7_val_en_passcode_self", [
            "Harbor Trust settings: Type one-time passcode 572839 strictly inside mobile netbanking to finish gas payee addition.",
            "Meridian Coop alert: Enter 6-digit OTP 819204 solely inside the logged-in application window to confirm standing order.",
            "Solstice Bank verification: Key in passcode 463918 within your official portal screen to authorize utility autopay.",
        ]),

        # --- 2. Benign EN fraud-caution & digital-hygiene advisories ---
        ("train", "english", 0, "v7_tr_en_caution_hygiene", [
            "Harbor Caution Note: Disregard messages pushing instant web verification; staff never direct patrons to read digits over audio calls.",
            "Meridian Digital Hygiene Tip: Ignore unsolicited links demanding urgent e-KYC upload; open official portals independently.",
            "Solstice Cyber Note: Representatives never instruct cardholders to voice security codes or speak passcodes aloud.",
            "Evergreen Trust Bulletin: Dismiss popups urging rapid browser login for PAN checks; verify standing only inside your own app.",
            "Oakwood Caution Notice: Fraud calls imitate audit desks asking to dictate login codes aloud—end such calls promptly.",
            "Crestline Security Reminder: Do not tap shortened web URLs alleging frozen savings accounts; call your branch desk if worried.",
            "Banyan Digital Hygiene: Treat messages hurrying instant KYC renewal links with skepticism; our portal hosts authentic alerts.",
            "Pinnacle Card Caution: No advisor ever directs you to utter verification numbers aloud or enter PINs on external pages.",
        ]),
        ("calibration", "english", 0, "v7_cal_en_caution_hygiene", [
            "Cedar Caution Note: Ignore alerts pressing immediate web-link login; bank officers never ask patrons to speak digits aloud.",
            "Metro Digital Hygiene Tip: Do not tap unknown URLs demanding quick KYC submission; verify updates inside the official portal.",
        ]),
        ("validation", "english", 0, "v7_val_en_caution_hygiene", [
            "Harbor Digital Hygiene Alert: Never open shortened links claiming emergency PAN checks; inspect notices strictly in-app.",
            "Meridian Caution Note: Staff never instruct customers to speak single-use passcodes aloud or click web verification links.",
            "Solstice Awareness Tip: Disregard urgent messages forcing e-KYC web submission; authentic notices sit inside your dashboard.",
        ]),

        # --- 3. Benign EN concise OD / credit headroom / standby line snapshots ---
        ("train", "english", 0, "v7_tr_en_od_headroom", [
            "Harbor Bank OD ledger: Drawn balance INR 0.00 against approved standby facility INR 45,000.00.",
            "Solstice overdraft summary: Current utilized line INR 1,250.00 out of sanctioned reserve limit INR 60,000.00.",
            "Oakwood savings & OD snapshot: Cleared deposit Rs. 24,800.00; unutilized credit standby INR 30,000.00.",
            "Crestline Credit line status: Unspent revolving quota stands at INR 82,000.00 against INR 1,00,000.00 cap.",
            "Meridian flexi-cash report: Active overdraft draw Rs. 0.00; available standby margin Rs. 55,000.00.",
        ]),
        ("calibration", "english", 0, "v7_cal_en_od_headroom", [
            "Banyan Bank OD summary: Drawn principal INR 0.00; unutilized standby limit INR 50,000.00 at end of day.",
        ]),
        ("validation", "english", 0, "v7_val_en_od_headroom", [
            "Evergreen Bank OD snapshot: Drawn principal INR 0.00, available standby quota INR 35,000.00 today.",
            "Pinnacle Credit headroom: Unspent spending line INR 74,500.00 against Rs. 90,000.00 total limit.",
        ]),

        # --- 4. Benign HI bill-payment OTP & profile-verification OTP notices ---
        ("train", "hinglish", 0, "v7_tr_hi_bill_otp", [
            "Metro bijli bill INR 890.00 chukane ke liye Harbor verification code 429105 aaya hai; call karne walon ko bilkul na batayein.",
            "Horizon gas bill Rs. 640.00 bharne hetu Solstice OTP 518392 bheja gaya hai; kisi phone adhikari ko hargiz mat dena.",
            "Pinnacle broadband Rs. 799.00 jama karne ke liye aapka confirmation OTP 730418 hai; anjaan vyakti ko na batayein.",
            "Sunrise Mart order Rs. 1,120.00 poora karne aapka login OTP 682940 aaya hai; kisi caller se share na karein.",
            "Banyan Cooperatives profile setup hetu 6-ankon ka OTP 904126 bheja gaya; yeh digits hamesha gupt rakhein.",
            "Evergreen paani bill Rs. 310.00 ke payment hetu secret code 384920 aaya hai; phone par kisi ko bol kar na sunayein.",
            "Oakwood recharge INR 499.00 confirm karne ke liye SMS OTP 275819 aaya; staff bhi yeh number nahi poochta.",
            "Crestline telecom bill Rs. 550.00 payment hetu verification token 619043 jaari hua; message kisi ko forward mat karein.",
        ]),
        ("calibration", "hinglish", 0, "v7_cal_hi_bill_otp", [
            "Harbor bijli bill Rs. 720.00 jama karne ke liye verification OTP 830291 aaya hai; call karne walon ko hargiz na batayein.",
            "Solstice merchant bill INR 950.00 ke liye one-time code 501924 bheja gaya hai; yeh anjaan callers ko mat batao.",
        ]),
        ("validation", "hinglish", 0, "v7_val_hi_bill_otp", [
            "Metro light bill INR 810.00 pay karne ke liye Meridian verification OTP 394810 aaya; kisi caller ko hargiz na dein.",
            "Oakwood cable bill Rs. 540.00 poora karne ka OTP 749102 bheja gaya hai; call par poochne walon ko kabhi na batayein.",
            "Banyan Pay profile KYC login ke liye 615029 one-time code aaya hai; anjaan vyakti ko yeh digits mat batana.",
        ]),

        # --- 5. Benign HI awareness (collect not needed & defensive hangup) ---
        ("train", "hinglish", 0, "v7_tr_hi_awareness_collect_hangup", [
            "Harbor Pay savdhani: Khate mein rakam aane par collect notification accept karna ya UPI PIN daalna kabhi zaroori nahi hota.",
            "Solstice Bank jaagrukta: Agar koi galat kati rashi wapas dilane ke bahane phone par code sunane ko kahe to turant phone rakh dein.",
            "Meridian niyam: Paisa paane hetu incoming payment collect popup approve karna zaroori nahi hota; aisa bolne par call kaat dein.",
            "Evergreen suraksha soochna: Koi vyakti refund ka lalach de kar SMS token maange ya bolne ko kahe to turant call band kar dein.",
            "Oakwood Pay tip: Cashback ya prize milne par kabhi UPI PIN bharna zaroori nahi hota; thagon ke collect alert ignore karein.",
            "Crestline grahak alert: Galat charge hatane ke naam par mobile code padhne ko kehne wale caller se turant phone disconnect karein.",
            "Banyan Trust sandesh: Receive payment ke liye request accept karna ya PIN dalna aavashyak nahi hota; khud app ledger dekhein.",
            "Pinnacle Bank savdhani: Anjaan vyakti refund processing ke liye code dikhane ya sunane ko bole to bharosa na kar turant phone rakh dein.",
        ]),
        ("calibration", "hinglish", 0, "v7_cal_hi_awareness_collect_hangup", [
            "Cedar Pay savdhani: Khate mein paise lene par collect request accept karna ya PIN daalna kabhi zaroori nahi hota.",
            "Metro Bank jaagrukta: Koi galat charge lautane ke bahane SMS code sunane ko kahe to turant phone rakh dein.",
        ]),
        ("validation", "hinglish", 0, "v7_val_hi_awareness_collect_hangup", [
            "Harbor suraksha: Paise receive karne ke samay UPI PIN bharna ya payment prompt approve karna zaroori nahi hota.",
            "Solstice jaagrukta: Agar koi caller penalty refund karne ke bahane verification code sunane ko bole to turant phone rakh dein.",
            "Evergreen savdhani: Incoming payment lene ke liye kisi bhi collect alert ko accept karna aavashyak nahi hai.",
        ]),

        # --- 6a. Scam Counter: EN URL-less hold/restriction + card number & CVV demand ---
        ("train", "english", 1, "v7_tr_en_hold_cvv_nourl", [
            "Harbor Fin warning: Account XX4812 placed under hold! Reply urgently with full debit card number and CVV to prevent shutdown.",
            "Solstice Credit restriction: Savings line XX9102 paused after risk alert! Text back complete card digits and CVV right away.",
            "Meridian Bank notice: Card facility restricted tonight! Send full 16-digit card number and expiry with CVV now to lift freeze.",
            "Evergreen Finance alert: Wallet A/c XX3094 put on hold! Reply immediately with ATM card number, CVV, and expiry before closure.",
            "Oakwood Trust freeze alert: Account access halted over suspicious login! Respond urgently with card details and CVV to avoid closure.",
            "Crestline Bank suspension notice: Debit A/c XX5520 put on hold! Reply right now with full card number and security CVV.",
        ]),
        ("calibration", "english", 1, "v7_cal_en_hold_cvv_nourl", [
            "Banyan Fin restriction: A/c XX7180 placed on hold! Reply urgently with complete card number and CVV to escape closure.",
            "Cedar Trust alert: Account XX6204 restricted today! Reply immediately with full card digits, expiry, and CVV to reopen.",
        ]),
        ("validation", "english", 1, "v7_val_en_hold_cvv_nourl", [
            "Harbor Card notice: Account XX8402 placed on temporary hold! Reply urgently with full debit card number and CVV to keep active.",
            "Solstice Bank restriction: Savings account placed on hold tonight! Send full card number and CVV right now to prevent termination.",
        ]),

        # --- 6b. Scam Counter: Numeric OTP/code embedded WITH link or active sharing demand ---
        ("train", "english", 1, "v7_tr_en_code_plus_demand", [
            "Harbor security alert: OTP 482910 generated to block unauthorized spend—forward OTP 482910 immediately at https://bit.ly/harbor-otp.",
            "Solstice dispute team: Confirmation passcode 739104 issued; reply with code 739104 right now so our agent halts Rs. 5,900 debit.",
            "Meridian KYC portal: Enter login code 582019 on https://meridian-verify.example urgently before midnight account suspension.",
            "Aapka transaction OTP 641920 aaya hai; galat Rs. 4,500 charge rokne ke liye abhi SMS code 641920 yahan reply karein.",
            "Solstice refund code 391048 bheja gaya hai; paisa wapas lene abhi https://bit.ly/sol-claim par OTP 391048 submit karo.",
        ]),
        ("calibration", "english", 1, "v7_cal_en_code_plus_demand", [
            "Oakwood fraud unit: Refund OTP 827104 triggered—send back passcode 827104 immediately to release INR 3,200 into your A/c.",
        ]),
        ("validation", "hinglish", 1, "v7_val_hi_code_plus_demand", [
            "Harbor support desk: Cancellation OTP 519284 bheja gaya hai; atka paisa pane ke liye turant code 519284 reply mein bhej do.",
            "Banyan security check: Passcode 638192 generated—submit token immediately via https://banyan-fix.example to avoid card block.",
        ]),

        # --- 6c. Scam Counter: Contrast-pivot EN/HI ---
        ("train", "english", 1, "v7_tr_en_contrast_extra", [
            "Security advisories warn never disclose passcodes loosely. Still, message back your verification OTP right now to settle cashback.",
            "Fraud notices state representatives never ask for PINs; nevertheless, reply with your 6-digit token now to stop debit.",
            "Banks advise guarding login digits safely. Yet dictate your confirmation code over voice right now so refund processes.",
            "Suraksha sandesh kehta hai password mat baantein, lekin apna atka cashback paane ke liye OTP turant message par bhejein.",
        ]),
        ("calibration", "hinglish", 1, "v7_cal_hi_contrast_extra", [
            "Jaagrukta niyam bolta hai kisi ko secret code mat do, phir bhi galat charge hatane OTP turant yahan reply kar do.",
        ]),
        ("validation", "english", 1, "v7_val_en_contrast_extra", [
            "Caution guidelines remind holders never reveal secrets; however, send your 6-digit OTP right now to unblock reversal.",
        ]),
    ]

    rows = []
    idx = 1
    for split, lang, label, family, texts in specs:
        for text in texts:
            rows.append({
                "id": f"v7d{idx:03d}",
                "split": split,
                "label": label,
                "language": lang,
                "family": family,
                "source": "synthetic_v7_dev",
                "text": text,
            })
            idx += 1
    return rows


def build_v7_holdout() -> list[dict]:
    """Build fresh unseen 240 labeled (120 EN, 120 HI) + 24 ambiguous holdout messages.

    Uses 100% fresh unseen entities: Chilika Bank, Vaitarna Trust, Tapti Pay, Hampi Card,
    Mysuru Mart, Saryu Express, Koyna Power, Bhima Water, Puri Rail, Ladakh Telecom,
    Zuari Fin, Rishikesh Hospital.
    """
    specs = [
        # ==================== ENGLISH BENIGN (60 = 10 categories x 6) ====================
        ("english", 0, "otp_delivery", "v7h_en_otp", "ctrl7_otp_1", [
            "Chilika Bank single-use OTP 492817 issued to view your online locker ledger. Treat these digits confidential.",
            "Vaitarna Trust alert: Temporary code 835104 generated for INR 1,490.00 spend at Mysuru Mart. Never pass this to any caller.",
            "Tapti Pay settings: Key in passcode 619204 strictly inside our official mobile application screen to save electricity payee.",
            "620419 is your portal code for Hampi Card alerts inside Vaitarna online login. Staff never phone to request it.",
            "Rishikesh Hospital billing OTP 731845 valid for five minutes on Tapti checkout. Refuse anyone asking for digits.",
            "Chilika confirmation: Enter temporary passcode 904518 inside mobile netbanking window to whitelist Koyna utility mandate.",
        ]),
        ("english", 0, "fraud_awareness", "v7h_en_awareness", None, [
            "Chilika Bank Bulletin: Tricksters spread phony debit freeze warnings and spoofed KYC pages. Officers never ask passwords or PINs.",
            "Vaitarna Cyber Hygiene Alert: Do not tap shortened web URLs urging sudden e-KYC upload; open official app banking directly.",
            "Hampi Card Caution Note: Disregard alerts forcing instant web-link verification; advisors never ask patrons to speak digits aloud.",
            "Tapti Pay Safety Tip: Cheaters push payment collect notifications disguised as gift payouts; no PIN approves incoming money.",
            "Zuari Fin advisory: Impostors mask caller extensions pretending blocked accounts. Reject screen-sharing tools and hang up immediately.",
            "Chilika customer tip: Verify suspect billing notices inside app history rather than reading SMS passcodes over incoming calls.",
        ]),
        ("english", 0, "debit_credit_receipt", "v7h_en_tx_receipt", None, [
            "Chilika Bank: Savings A/c XX4190 credited INR 22,500.00 via NEFT Ref CK8821049. Available balance INR 61,430.00.",
            "Vaitarna Trust: Debit of Rs. 1,380.00 recorded on A/c XX7305 at Mysuru Mart on 23-Nov-26. Call 1800-510-7722 if unrecognized.",
            "Hampi Credit Card XX5902 charged INR 2,190.00 at Saryu Express Logistics on 22-Nov-26. Credit headroom left Rs. 88,400.00.",
            "Salary settlement: Account ending 4190 with Chilika Bank received INR 48,000.00 through IMPS Ref 991827364501.",
            "Ticket spend: Puri Rail reservation Rs. 920.00 paid using Vaitarna debit card XX8140 on 22-Nov-26.",
            "Quarterly interest payout: Zuari Fin posted INR 512.40 savings interest directly into account XX3628.",
        ]),
        ("english", 0, "failed_payment_reversal", "v7h_en_reversal", "ctrl7_refund_1", [
            "Chilika Settlement: Declined Mysuru Mart swipe of Rs. 1,240.00 reversed cleanly into A/c XX4190 without action.",
            "Vaitarna Auto-Credit: Unsuccessful Puri Rail ticket amount INR 1,050.00 restored to savings funds; zero approval code needed.",
            "Tapti Pay refund note: Failed UPI transfer of INR 1,680.00 routed back automatically into linked checking balance.",
            "Mysuru Mart credit update: Rs. 860.00 for canceled kitchen order returned straight to card ending 7305.",
            "Saryu Express reimbursement: INR 1,410.00 for voided parcel booking deposited into Chilika savings A/c XX4190.",
            "Hampi Card adjustment: Duplicate hotel POS pre-auth of Rs. 3,120.00 cleared off statement ledger without calling support.",
        ]),
        ("english", 0, "user_card_block", "v7h_en_user_block", "ctrl7_block_1", [
            "Chilika Bank update: Manual in-app block submission for debit card XX8140 finished smoothly with zero extra steps.",
            "Vaitarna Trust: Per your login instruction, ATM card XX7305 was turned off; order replacement card anytime inside Card Control.",
            "Tapti Card settings: You paused international swipe and locked card XX5902 from app toggles; re-enable whenever ready.",
            "Zuari Fin confirmation: Lost swipe card XX3628 disabled following your request; replacement dispatch arrives within five days.",
            "Hampi Card notice: Self-initiated freeze action on card ending 5902 completed cleanly inside mobile settings.",
            "Vaitarna record: As initiated by your mobile session, contactless access on ending 4190 has been disabled cleanly.",
        ]),
        ("english", 0, "branch_kyc_appointment", "v7h_en_branch_kyc", None, [
            "Chilika Branch Desk: Scheduled periodic KYC update slot at Panaji branch is confirmed for 15-Dec-26 at 10:30 AM.",
            "Vaitarna Trust update: Paperwork submitted at Cuttack Civil branch cleared KYC compliance audit smoothly with nothing remaining.",
            "Hampi Card status: Appreciate your visit to Mysore Palace desk; annual identity documents cleared inspection and stand current.",
            "Zuari Fin booking: Assigned counter desk #05 at Dibrugarh branch for scheduled Know Your Customer check on 16-Dec-26.",
            "Tapti Trust record: Counter appointment booked for routine KYC review on 17-Dec-26 at 11:15 AM; carry original ID card.",
            "Chilika completion note: Yearly KYC review handed in at reception counter cleared verification completely.",
        ]),
        ("english", 0, "statement_notification", "v7h_en_statement", None, [
            "Chilika Bank monthly file: November statement PDF for A/c XX4190 uploaded inside https://docs.chilika.example/statements.",
            "Vaitarna savings document: Review quarterly passbook ledger online through https://portal.vaitarna.example/passbook.",
            "Hampi Card cycle invoice: Monthly bill for XX5902 archived at https://billing.hampicard.example/nov-invoice.",
            "Zuari Fin annual report: Tax interest certificate ready inside https://archive.zuarifin.example/tds-report.",
            "Ladakh Telecom receipt: Postpaid monthly invoice #LT71042 worth Rs. 599.00 published at https://bills.ladakhtel.example/pdf.",
            "Tapti savings statement: Half-yearly fee sheet placed cleanly at https://docs.taptipay.example/fees.",
        ]),
        ("english", 0, "upi_notification", "v7h_en_upi", None, [
            "Tapti Pay alert: Sent INR 730.00 from Chilika A/c XX4190 to Rishikesh Pharmacy via Ref 662019384712.",
            "Through Vaitarna UPI rail: Credited INR 1,560.00 straight into savings ending 7305 (UTR 881029384611).",
            "Paid Rs. 640.00 smoothly using Tapti handle toward Bhima Water Counter on 23-Nov-26. Ref #551928374610.",
            "Chilika UPI credit: Rs. 2,890.00 arrived from M. Kulkarni into XX4190; inspect updated ledger inside official app.",
            "Utility UPI receipt: Koyna Power acknowledged INR 1,420.00 payment via Txn Ref 771029384712.",
            "Monthly standing mandate: Ladakh Telecom Rs. 399.00 plan cleared cleanly from Vaitarna A/c XX7305.",
        ]),
        ("english", 0, "balance_notification", "v7h_en_balance", None, [
            "Chilika savings ledger: Cleared funds in A/c XX4190 at close of 23-Nov-26 equal INR 61,430.00.",
            "Vaitarna balance update: Checking A/c XX7305 holds Rs. 29,480.25 clear cash as of morning settlement.",
            "Hampi Card credit headroom: Unspent spending line on XX5902 sits at Rs. 88,400.00 against Rs. 1,10,000.00 cap.",
            "Zuari Fin OD snapshot: Drawn overdraft principal INR 0.00, unutilized standby line INR 42,000.00.",
            "Tapti Pay ledger: Available wallet funds stand at INR 4,120.00 inside mobile app dashboard.",
            "Chilika account XX4190 summary: Clear balance INR 19,850.00 with zero pending uncleared items.",
        ]),
        ("english", 0, "delivery_utility_benign", "v7h_en_utility", None, [
            "Mysuru Mart order #MM88210 dispatched through Saryu Express and delivers tomorrow afternoon; track inside shopping app.",
            "Koyna Power update: Bill payment Rs. 1,580.00 posted against Consumer #KP55102. Next meter cycle 23-Dec-26.",
            "Rishikesh Hospital desk: Orthopedic follow-up set Saturday 05:00 PM with Dr. Nair; carry scan printout.",
            "Bhima Water confirmation: Monthly supply bill Rs. 410.00 cleared cleanly under Account BW31902. Zero dues left.",
            "Puri Rail notice: Coach B3 Berth 22 confirmed on Express 12802 departing Thursday 07:15 AM.",
            "Ladakh Telecom alert: Monthly 50 GB mobile internet combo refreshed cleanly for next 28 days.",
        ]),

        # ==================== ENGLISH SCAM (60 = 10 categories x 6) ====================
        ("english", 1, "account_block_threat", "v7h_en_block", "ctrl7_block_1", [
            "URGENT Chilika notice: Your savings account freezes midnight! Tap https://bit.ly/chilika-unlock right away to verify login.",
            "Vaitarna security alert: Debit card XX7305 deactivated after alien access! Sign in via https://vaitarna-fix.example now to prevent closure.",
            "Hampi Card emergency: Credit line ends inside 2 hours unless reactivated at https://t.co/hampi-sec right now.",
            "Zuari Fin restriction: A/c XX3628 placed on hold! Reply urgently with full card number and CVV to stop shutdown.",
            "CRITICAL Tapti Pay alert: Wallet shuts permanently tonight unless credentials confirmed at https://tinyurl.com/tapti-unblock.",
            "Chilika card warning: ATM access frozen temporarily! Text back PIN and expiry month right now to unlock.",
        ]),
        ("english", 1, "otp_pin_solicitation", "v7h_en_otp", "ctrl7_otp_1", [
            "Chilika Fraud Desk: Send your 6-digit OTP right now so team halts an unauthorized Rs. 5,900.00 transfer.",
            "Vaitarna care unit: Reply immediately with ATM PIN and CVV to cancel rogue POS charge on your card.",
            "Hampi Support desk: Text back 4-digit MPIN together with confirmation code urgently so bonus points do not lapse.",
            "Keep login codes secret cleanly. However, forward your 6-digit OTP right now to settle duplicate fee refund.",
            "Tapti Helpdesk: Message back the 6-digit SMS security token right away to activate higher transfer cap.",
            "Advisories warn never expose secret PINs; yet reply with verification OTP immediately to claim pending rebate.",
        ]),
        ("english", 1, "fake_kyc_link", "v7h_en_kyc", None, [
            "Chilika alert: KYC compliance expired! Open https://bit.ly/chilika-kyc inside two hours or online banking terminates.",
            "Vaitarna e-KYC urgent notice: Upload Aadhaar and PAN details via https://vaitarna-ekyc.example right away to escape freeze.",
            "Hampi Credit warning: Re-verify KYC information promptly at https://tinyurl.com/hampi-kyc else card deactivates tonight.",
            "Zuari KYC portal: Submit banking password and PAN digits immediately at https://zuari-kyc.example to prevent hold.",
            "Tapti Trust warning: Re-KYC verification failed; click https://rb.gy/tapti-kyc immediately so incoming credits keep working.",
            "Chilika compliance desk: Finish emergency KYC recheck tonight urgently or savings netbanking shuts permanently.",
        ]),
        ("english", 1, "fake_refund", "v7h_en_refund", "ctrl7_refund_1", [
            "Mysuru Mart refund ready cleanly: Approve incoming collect prompt worth INR 1,240 inside UPI app right now to credit A/c XX4190.",
            "Saryu Express delay credit Rs. 2,350 sanctioned: Accept pending collect popup immediately and confirm UPI PIN.",
            "Koyna Power overcharge return INR 1,580 queued! Authorize collect payment request on Tapti Pay using PIN to fetch payout.",
            "Hampi annual charge refund Rs. 999 approved—tap Authorize on our incoming collect popup immediately for deposit.",
            "Protect banking secrets from strangers; however, accept this Rs. 1,850 collect request right now to settle duplicate fee.",
            "Puri Rail cancellation rebate INR 1,320 cleared: Approve payment collect request promptly to pull cash into savings.",
        ]),
        ("english", 1, "read_aloud_otp", "v7h_en_read_aloud", None, [
            "Billing verification calling: Rs. 3,899 membership charge hits Hampi Card tonight. Speak the 6-digit abort code aloud on call now.",
            "Chilika security desk: We sent a cancel passcode to stop rogue debit. Read out every digit of that security code aloud right now.",
            "Dispute resolution agent calling: Dictate the single-use reversal code texted just now so we stop INR 4,900 deduction.",
            "Recovery team regarding Rs. 2,650 excess charge: Read aloud the SMS verification code over voice immediately.",
            "Auto-debit stop desk: Card deducts Rs. 1,999 in 4 minutes—speak out the inbox confirmation code aloud right now.",
            "Security notice warns guard secrets, yet dictate your 6-digit cancel OTP aloud on this call immediately to stop theft.",
        ]),
        ("english", 1, "family_transfer_urgent", "v7h_en_family", None, [
            "Hey bro stuck at highway toll booth with dead phone borrowing guard's hotspot. Wire 4,100 rs via UPI right away, signal cuts here.",
            "Mom my regular SIM died during rain and I need INR 8,200 wired urgently for clinic billing; skip calling back, 1 percent battery left.",
            "Dad texting from classmate's handset since mine shattered outside lab. Transfer Rs. 5,900 urgently via Tapti UPI now, speaker is dead.",
            "Auntie lost my main handset at bus stand and using security office number. Please wire INR 4,600 right now to this UPI ID, cannot talk inside ward.",
            "Sis urgent—my SIM failed outstation and using cabbie's spare handset. Transfer Rs. 5,400 immediately via wallet QR, call once home.",
            "Ma borrowing co-passenger's phone after mine died near station. Kindly send INR 6,900 urgently via UPI for booking, do not ring this number.",
        ]),
        ("english", 1, "delivery_customs_scam", "v7h_en_delivery", None, [
            "Saryu Express Customs notice: International courier held at port; clear INR 690 duty at https://bit.ly/saryu-duty before auction.",
            "Mysuru Cargo update: House street incomplete on docket #MY9032—pay Rs. 45 redelivery fee via https://saryu-rebook.example immediately.",
            "Urgent import release warning: Packet returns overseas tonight! Submit INR 880 customs tax at https://tinyurl.com/port-duty right away.",
            "Express depot alert: Warehouse holding charge Rs. 520 overdue on parcel; settle via https://rb.gy/cargo-fee before 6 PM.",
            "Last attempt notice from Saryu Dispatch: Verify address PIN and remit INR 290 reroute fee at https://saryu-ship.example immediately.",
            "Customs clearance hold: Package stopped over missing KYC upload—pay Rs. 750 tariff at https://customs-rebook.example urgently.",
        ]),
        ("english", 1, "prize_lottery_scam", "v7h_en_prize", None, [
            "JACKPOT ALERT! Your SIM won Chilika Grand Lucky Draw INR 7,00,000! Claim immediately on https://bit.ly/chilika-win.",
            "Tapti Festive Raffle: Chosen winner of Rs. 50,000 voucher + handset! Pay Rs. 499 shipping fee at https://tapti-claim.example.",
            "Hampi Card Reward Jackpot: INR 32,000 bonus expires midnight—visit https://tinyurl.com/hampi-win and confirm CVV.",
            "Ladakh Telecom Lucky Draw: You grabbed tablet + Rs. 1,25,000 prize! Remit handling charge right away via https://t.co/ladakh-prize.",
            "Vaitarna Bumper Draw: INR 2,20,000 cash waiting against your mobile—submit bank A/c and Rs. 999 GST at https://vaitarna-win.example.",
            "Festive prize INR 18,000 unlocked inside Tapti Wallet! Enter UPI PIN on https://rb.gy/fest-win right now.",
        ]),
        ("english", 1, "job_scam", "v7h_en_job", None, [
            "Part-time catalog tagging vacancy! Zero prior skill needed, make INR 3,600 daily via Telegram desk—join now with Rs. 950 kit deposit.",
            "Work from home brand rating job offer: Earn Rs. 2,800–4,800 daily! Text Telegram coordinator immediately and pay Rs. 780 slot fee.",
            "Remote video review job hiring today! Guaranteed Rs. 3,200 daily income; open https://bit.ly/task-join to buy starter pass.",
            "URGENT online store promoter role: Daily wage INR 4,300 from phone; message Telegram trainer and transfer Rs. 899 registration fee.",
            "Boutique resort portal seeking freelance reviewers! Daily salary Rs. 3,900; remit Rs. 1,100 kit deposit via https://tinyurl.com/work-join.",
            "Immediate task coordinator hiring at Mysuru Desk! Earn Rs. 3,000 daily; wire Rs. 690 security fee to activate earnings.",
        ]),
        ("english", 1, "utility_disconnect_scam", "v7h_en_utility_scam", None, [
            "URGENT Koyna Power notice: Home electric meter cuts tonight at 9:30 PM over unverified previous bill. Ring engineer 9811223344 now.",
            "Bhima Water shutoff warning: Residential tap line disconnects today—verify receipt via https://bit.ly/bhima-stay right away.",
            "Koyna Power Desk Alert: Smart meter shuts off tonight; share UPI PIN or help code with officer 9700223344 right now.",
            "DISCONNECT ALERT from Power Office: Last invoice missing verification! Visit https://tinyurl.com/koyna-cut immediately to keep power.",
            "Ladakh Telecom barring notice: Primary SIM terminates permanently inside 3 hours! Call supervisor 9822445511 urgently.",
            "Municipal line cutoff warning: Pay INR 19 clearance charge immediately via https://rb.gy/meter-stay or face blackout tonight.",
        ]),

        # ==================== HINGLISH BENIGN (60 = 10 categories x 6) ====================
        ("hinglish", 0, "otp_delivery", "v7h_hi_otp", "ctrl7_hi_otp_1", [
            "Tapti Wallet sign-in ki pushti ke liye 619402 code jaari kiya gaya; kisi ko phone ya SMS par mat dikhana.",
            "847210 aapke Vaitarna netbanking session ka suraksha OTP hai; agar koi staff ban kar maange tab bhi mana karein.",
            "Mysuru Mart par Rs. 1,350.00 kharidari ke liye Hampi OTP 502914 mila; apna gopniya code kabhi kisi ko na dein.",
            "Rishikesh Clinic fees INR 920.00 pay karne hetu 713825 verification digits screen par likhein, kisi se share mat karein.",
            "Chilika Bank mein naya payee jodne ka single-use code 394812 hai; anjaan vyakti ko yeh digits hargiz na batana.",
            "Koyna bijli bill Rs. 790.00 poora karne aapka SMS OTP 518294 aaya; kisi caller ko bol kar batane ki galti na karein.",
        ]),
        ("hinglish", 0, "fraud_awareness", "v7h_hi_awareness", None, [
            "Tapti digital suraksha tips: Khate mein payment receive hote waqt UPI PIN dalna ya collect prompt accept karna kabhi zaroori nahi hota.",
            "Chilika cyber jaagrukta: Koi caller tax ya galat rashi lautane ke naam par SMS token sunane ko bole to turant call kaat dein.",
            "Vaitarna Trust caution: Apna MPIN, ATM password aur login OTP kisi se na baantein; bank staff kabhi call karke yeh sab nahi poochta.",
            "Hampi digital hygiene: Anjaan URL khol kar e-KYC verify karne ke lalach se bachein; sahi updates sidhe mobile app par dekhein.",
            "Zuari Fin suraksha chetavani: Remote screen control apps download na karein aur cashback lene ke liye PIN kabhi mat bharna.",
            "Grahak jaagrukta sandesh: Khata band hone wali nakli calls aur spam links par bharosa na kar ke seedhe toll-free par poochein.",
        ]),
        ("hinglish", 0, "debit_credit_receipt", "v7h_hi_tx_receipt", None, [
            "Chilika Bank sandesh: Bachat khata XX4190 mein NEFT Ref CK8821049 dwara Rs. 16,400.00 aaye; kul shesh INR 61,430.00 bacha hai.",
            "Vaitarna card soochna: Debit XX7305 se Mysuru Mart par Rs. 1,380.00 kharch darj hue; agar galat lage to app se report karein.",
            "Hampi Card XX5902 par Saryu Cargo ka Rs. 2,190.00 payment darj hua; aapki uplabdh kharch limit abhi Rs. 88,400.00 baki hai.",
            "Zuari savings khate mein aaj Rs. 6,100.00 prapt hue (IMPS UTR 882910475612); poori passbook mobile portal par dekhein.",
            "Vaitarna card XX8140 se Rishikesh Pharmacy par Rs. 940.00 ka bill chukaya gaya; madad ke liye 1800-510-7722 par sampark karein.",
            "Chilika account XX4190 mein is quarter ka savings byaj INR 512.40 seedha jama kar diya gaya hai.",
        ]),
        ("hinglish", 0, "failed_payment_reversal", "v7h_hi_reversal", "ctrl7_hi_refund_1", [
            "Tapti UPI refund alert: Adhoori rahi Rs. 1,240.00 rashi bina kisi PIN ya approval ke aapke Chilika khate mein laut aayi hai.",
            "Mysuru Mart order radd hone se Rs. 860.00 seedhe Vaitarna savings balance mein jama ho gaye; koi extra process baaki nahi.",
            "Puri Rail ki radd booking ke Rs. 1,050.00 aapke linked account mein wapas aa chuke hain, kisi external link par click mat karein.",
            "Hampi Credit Card par do baar kata Rs. 3,120.00 merchant shulk aapke monthly bill mein automatically adjust kar diya gaya hai.",
            "Koyna bijli transaction fail hone par Rs. 1,420.00 khud-ba-khud wapas Chilika khata ending 4190 mein pahunch gaye.",
            "Saryu courier booking cancel hone ka pura Rs. 1,410.00 wapsi payment aaj aapke mool bank khate mein credit hua.",
        ]),
        ("hinglish", 0, "user_card_block", "v7h_hi_user_block", "ctrl7_hi_block_1", [
            "Chilika card control: App mein aapke dwara ki gayi manual lock request ke baad debit card XX8140 band ho chuka hai.",
            "Vaitarna soochna: Customer portal par aapke nirdesh ke anusar ATM card XX7305 ab disable kar diya gaya hai.",
            "Tapti mobile settings: Aapne khud app ke andar card XX5902 par swipe aur international upyog rok diya hai.",
            "Card kho jaane par aapki complaint par Zuari debit XX3628 block hua; naya card postal dak se 5 din mein milega.",
            "Hampi Credit status: Mobile app mein aapne card XX5902 temporary pause kar diya hai; zaroorat padne par khud chalu karein.",
            "Vaitarna login mein aapke request se debit card ending 4190 freeze ho gaya hai; chalu karwane branch ya app control use karein.",
        ]),
        ("hinglish", 0, "branch_kyc_appointment", "v7h_hi_branch_kyc", None, [
            "Vaitarna Desk: Cuttack shaka counter par jama ki gayi aapki saalana KYC file verify aur approve ho chuki hai.",
            "Chilika Bank yaad-dilani: Panaji main branch mein aapki routine KYC check meeting 15-Dec subah 10:30 AM fix hui hai.",
            "Hampi Counter Update: Aapne shaka mein jo pehchan patra aur KYC kagaz diye unka verification poorn hokar record update ho gaya.",
            "Zuari Fin notification: Dibrugarh branch counter #05 par annual KYC verification ke liye aapka Somwar ka slot reserved hai.",
            "Tapti Trust soochna: Branch counter par aapki periodic KYC verification safaltapoorvak poorn ho gayi hai, reply na bhejein.",
            "Chilika reminder: Panaji branch desk par kal verification milan ke samay apna original photo ID zaroor saath layein.",
        ]),
        ("hinglish", 0, "statement_notification", "v7h_hi_statement", None, [
            "Chilika bachat khata XX4190 ka November maah ka PDF passbook statement https://docs.chilika.example/nov par uplabdh hai.",
            "Tapti Pay monthly kharch aur transaction hisab https://reports.taptipay.example/ledger par online dekha ja sakta hai.",
            "Vaitarna Trust quarterly ledger aur interest slip download karne hetu https://portal.vaitarna.example/passbook dekhein.",
            "Hampi Card XX5902 ka naya billing bill aur tax invoice https://billing.hampicard.example/nov-pdf par upload kiya gaya hai.",
            "Zuari Finance savings account ka vaarshik TDS praman-patra https://archive.zuarifin.example/tds par taiyar rakha hai.",
            "Ladakh Telecom postpaid plan ka maasik e-bill PDF https://bills.ladakhtel.example/monthly par ja kar dekh sakte hain.",
        ]),
        ("hinglish", 0, "upi_notification", "v7h_hi_upi", None, [
            "Tapti Pay dwara Rishikesh Medical Store ko Rs. 620.00 bheje gaye; is lenden ka UPI Ref 662019384712 hai.",
            "Vaitarna account ending 7305 mein Chilika UPI se Rs. 1,560.00 aaye hain (UTR 881029384611).",
            "Koyna bijli board ke Rs. 1,580.00 Tapti UPI (Ref 881029384611) se aapke khate dwara pay ho chuke hain.",
            "Mysuru Mart par Vaitarna QR scan karke Rs. 810.00 bhugtan safal hua; updated shesh mobile app mein dekhein.",
            "Aapke Chilika A/c XX4190 se Suresh ji ko UPI par Rs. 950.00 bheje gaye aur khata update ho chuka.",
            "Bhima paani vibhag ke Rs. 410.00 bill ka UPI settlement poora ho gaya hai (Ref 551928374610).",
        ]),
        ("hinglish", 0, "balance_notification", "v7h_hi_balance", None, [
            "Chilika savings A/c XX4190 mein aaj ke din-ant par kul uplabdh shesh INR 61,430.00 darj hua, koi hold nahi hai.",
            "Vaitarna Trust khata XX7305 ka naya clear cash balance subah sync ke baad Rs. 29,480.25 dikha raha hai.",
            "Hampi Card XX5902 par aapki baki kharch headroom seema Rs. 88,400.00 aur agla bill cycle 14-Dec ko hai.",
            "Tapti Pay wallet tatha jude bank balance ka sangrahit shesh INR 4,120.00 aapke app par uplabdh hai.",
            "Zuari account XX3628 mein bina kisi uncleared cheque ke Rs. 19,850.00 nikalne ke liye safe uplabdh hain.",
            "Chilika deposit tatha savings khata vivran aaj subah aapke mobile ledger mein update kar diya gaya hai.",
        ]),
        ("hinglish", 0, "delivery_utility_benign", "v7h_hi_utility", None, [
            "Mysuru Mart se aapka saaman Saryu Express dwara bheja ja chuka aur kal shaam ghar pahunchne ki ummeed hai.",
            "Koyna bijli vibhag: Consumer KP55102 par Rs. 1,580.00 jama ho gaye, agla meter reading bill 23-Dec ko banega.",
            "Rishikesh Aspataal clinic: Shanivar shaam 05:00 PM Dr. Nair ke saath checkup tay hai, purani reports lana na bhoolein.",
            "Bhima Jal board bill Rs. 410.00 safaltapoorvak chukta hua; aapke meter khate par ab koi baki rashi nahi.",
            "Ladakh Telecom mobile pack: 50 GB data tatha calling suvidha agle 28 din ke liye activate ho gayi hai.",
            "Puri Rail ticket soochna: Guruwar subah 07:15 AM gaadi 12802 mein Coach B3 Seat 22 confirm ho chuki hai.",
        ]),

        # ==================== HINGLISH SCAM (60 = 10 categories x 6) ====================
        ("hinglish", 1, "account_block_threat", "v7h_hi_block", "ctrl7_hi_block_1", [
            "Chilika emergency warning: Aaj raat 11 baje savings account freeze ho jayega! Turant https://bit.ly/chilika-block khol kar unblock karein.",
            "Vaitarna ATM alert: Card XX7305 sandigdh upyog se block hua hai, https://vaitarna-unlock.example par abhi card number daal kar bachayein.",
            "Hampi Credit Card agle 2 ghante mein deactivate hone wala hai! https://t.co/hampi-kyc par turant MPIN submit karein.",
            "Tapti wallet suraksha soochna: Khatre ke kaaran khata aaj band hoga, https://tinyurl.com/tapti-unfreeze par abhi password verify karein.",
            "Zuari bank khata nigrani alert: Account block hone se rokne ke liye abhi SMS reply mein card number aur CVV bhej dein.",
            "Chilika netbanking aaj raat hamesha ke liye radd ho rahi hai! Chalu rakhne 9811223344 par apna ATM PIN turant batayein.",
        ]),
        ("hinglish", 1, "otp_pin_solicitation", "v7h_hi_otp", "ctrl7_hi_otp_1", [
            "Chilika fraud unit: Aapke khate se Rs. 5,900 katne ja rahe hain, rukwane ke liye abhi aaya 6-digit OTP yahan reply karein.",
            "Vaitarna card department: Galat billing shulk wapas pane ke liye apna ATM PIN tatha CVV turant message mein bhejein.",
            "Hampi helpdesk se bol raha hoon: Limit badhane hetu mobile par bheja OTP aur date of birth abhi send karo.",
            "Bank niyam bolte hain secret code chhupayein, par Rs. 2,900 festive reward lene SMS par aaya OTP abhi reply karein.",
            "Tapti support desk: Wallet transaction seema badhane phone mein mila verification OTP aur MPIN turant likh kar bhejein.",
            "Advisories kehti hain password na baantein, lekin atka hua bonus turant khate mein dalwane verification code forward karo.",
        ]),
        ("hinglish", 1, "fake_kyc_link", "v7h_hi_kyc", None, [
            "Vaitarna grahak chetavani: Aaj online KYC verification na karne par aapki saari netbanking sevayein raat ko band ho jayengi.",
            "Chilika e-KYC antim alert: Turant https://bit.ly/chilika-ekyc khol kar PAN upload karein warna khata hamesha ke liye ruke.",
            "Hampi PAN jankari adhoori hai! https://tinyurl.com/hampi-pan par abhi details bharein nahi to debit aur credit card block hoga.",
            "Zuari KYC portal: Shaam 6 baje tak https://zuari-ekyc.example par login aur Aadhaar number bharo warna jama paisa rukega.",
            "Tapti e-KYC error: Wallet KYC nakaam rahi; salary aur credits chalu rakhne https://rb.gy/tapti-kyc par abhi verify karein.",
            "Chilika compliance desk: Emergency KYC aaj khatam ho rahi hai, bachne ke liye SMS reply mein card digits aur PIN bhejo.",
        ]),
        ("hinglish", 1, "fake_refund", "v7h_hi_refund", "ctrl7_hi_refund_1", [
            "Mysuru Mart refund manzoor hua: Rs. 1,240 khate mein lene ke liye Tapti UPI par aayi collect request abhi approve karein aur PIN bharo.",
            "Saryu Express der hone ka harjana Rs. 2,350 pane ke liye aapke mobile par aayi payment request accept karke PIN confirm karein.",
            "Rishikesh Aspataal mein extra kate Rs. 1,580 wapas lene abhi aayi collect notification accept karke UPI PIN daal dein.",
            "Hampi card annual shulk Rs. 999 refund lene ke liye screen par dikh raha incoming collect popup turant authorize karo.",
            "Ladakh recharge cashback Rs. 1,250 sidhe khate mein bhejne ke liye bheji gayi UPI collect request abhi accept karein.",
            "Secret code kisi ko mat dena, magar Rs. 2,600 wapsi lene ke liye incoming collect request turant approve dabao.",
        ]),
        ("hinglish", 1, "read_aloud_otp", "v7h_hi_read_aloud", None, [
            "Hampi Card billing unit bol rahi hoon, aaj Rs. 3,899 katne wala hai; cancel karne ke liye SMS wala code abhi padh kar sunao.",
            "Chilika security center: Videshi POS par Rs. 4,900 swipe hua hai, rokne ke liye mobile par bheja OTP turant bol kar suna dein.",
            "Puri Rail cancellation ke Rs. 1,950 chhutwane phone par bheja gaya security token bina deri call par padh kar batayein.",
            "Annual club renewal Rs. 2,199 aaj automatically katega; band karwane SMS se mila 6-digit code phone par bol kar batao.",
            "Zuari khate se galat insurance charge Rs. 2,899 hatane ke liye mobile inbox wala verification code abhi dictate karo.",
            "Niyam kehta hai OTP gupt rakho, phir bhi ruki rakam khate mein lene call par SMS confirmation code padh kar suna dein.",
        ]),
        ("hinglish", 1, "family_transfer_urgent", "v7h_hi_family", None, [
            "Bhaiya toll barrier par phans gaya, mera mobile switch off hai aur guard ka hotspot lekar likh raha. Abhi Rs. 4,100 UPI bhej do.",
            "Maa tez baarish mein mera handset aur SIM kharab ho gaya; ticket lene abhi Rs. 8,200 bhej do, battery 1% bachi hai call mat lagana.",
            "Papa dost ke doosre number se msg kar raha kyunki mera phone bus stand par gir ke toot gaya. Clinic mein abhi Rs. 8,300 UPI send karo.",
            "Didi mera phone display toot gaya aur mic band pada hai. Dawai lene abhi Rs. 4,600 is QR handle par bhejo, ghar aakar hisab karunga.",
            "Chacha batua aur mobile bazar mein chori ho gaya, canteen phone se likh raha. Jaldi Rs. 5,400 is UPI par wire karo, hospital mein phone na karna.",
            "Mummy train nikalne wali hai aur mera phone hang ho raha, co-passenger ke number se bheja. Abhi Rs. 6,100 UPI bhej do.",
        ]),
        ("hinglish", 1, "delivery_customs_scam", "v7h_hi_delivery", None, [
            "Saryu Express border alert: Videsh se aaya packet port par ruka hai; neelami se bachane Rs. 690 duty https://bit.ly/saryu-duty par bharo.",
            "Mysuru Mart courier soochna: Pata adhoora hone se parcel wapas ja raha; https://saryu-track.example khol kar Rs. 45 rebook charge dein.",
            "Saryu Logistics antim warning: Aaj sham aapka parcel radd ho jayega! Turant https://tinyurl.com/saryu-clear par address verify karo.",
            "Chilika import tax Rs. 880 jama na hone se packet zabt ho raha hai; turant https://rb.gy/port-pay khol kar card se bharo.",
            "Saryu delivery agent ko ghar nahi mila; live GPS location update karne aur Rs. 160 dene https://mysuru-ship.example link dabao.",
            "Gift parcel clear karwane Saryu cargo Rs. 990 fee abhi https://t.co/port-gift par online jama kar dein.",
        ]),
        ("hinglish", 1, "prize_lottery_scam", "v7h_hi_prize", None, [
            "MUBARAK! Aapke number par Chilika Mega Draw ka Rs. 7,00,000 jackpot laga hai! Paane ke liye https://bit.ly/chilika-win turant kholein.",
            "Tapti festive draw mein aapko Rs. 60,000 + smart TV inaam nikla! Courier bhejne Rs. 499 shulk https://tapti-draw.example par bharo.",
            "Hampi reward draw winner: Aapko Rs. 32,000 cash inaam mila—bank mein lene https://tinyurl.com/hampi-inaam par card aur CVV submit karo.",
            "Ladakh Telecom lucky draw mein tablet aur Rs. 1,25,000 jeete! Claim karne Rs. 899 GST shulk https://t.co/ladakh-inaam par turant bhejein.",
            "Vaitarna Bumper inaam Rs. 2,20,000 aaj raat samapt hoga; A/c number aur PIN https://vaitarna-lotto.example par abhi verify karein.",
            "Tapti Diwali bonus Rs. 18,000 sidhe khate mein pane https://rb.gy/tapti-spin khol kar apna UPI PIN enter karo.",
        ]),
        ("hinglish", 1, "job_scam", "v7h_hi_job", None, [
            "Part-time mobile catalog rating kaam! Bina degree roz Rs. 3,600 kamayi; Telegram join karke Rs. 950 kit deposit jama karein.",
            "Hampi Partner ghar-baithe rating naukri: Rozana Rs. 2,800 pakki salary! Abhi Telegram par sampark karein aur Rs. 780 slot fee bhejein.",
            "Mysuru Mart product review bharti! Daily payout Rs. 3,200 bank mein; shuru karne https://bit.ly/task-join par Rs. 890 pass lein.",
            "Social media post like job vacancy! Roz INR 4,300 phone se kamayein; Telegram mentor ko Rs. 900 registration fee bhejein.",
            "Mysuru digital assistant hiring: Do ghante kaam karke Rs. 3,000 kamayein; task unlock karne Rs. 690 security rashi turant send karo.",
            "Travel portal task work: Roz Rs. 3,900 guaranteed income; turant https://tinyurl.com/work-join khol kar Rs. 1,100 kit charge bharo.",
        ]),
        ("hinglish", 1, "utility_disconnect_scam", "v7h_hi_utility_scam", None, [
            "Koyna bijli vibhag urgent: Pichle bill ka record na milne se aaj raat 9:30 PM par light kategi. Abhi 9811223344 par engineer ko call karein.",
            "Bhima paani vibhag chetavani: Ghar ka water meter aaj raat band hoga; bachne ke liye https://bit.ly/bhima-unblock par bill verify karo.",
            "Koyna smart meter disconnect alert! Line chalu rakhne abhi https://tinyurl.com/koyna-stay khol kar Rs. 25 debit card se jama karein.",
            "Ladakh Telecom SIM barring notice: Aaj raat outgoing calls aur network band hone wala hai, rokne 9700223344 par OTP batayein.",
            "Koyna Bijli Office antim sandesh: Raat bijli band na ho iske liye screen share app daal kar 9822445511 ko token batayein.",
            "Koyna meter update chetavani: Supply band hone se pehle https://rb.gy/meter-stay khol kar consumer ID aur PIN bharo.",
        ]),

        # ==================== AMBIGUOUS HOLDOUT (24 = 12 EN + 12 HI, label=None) ====================
        ("english", None, "ambiguous_callback", "v7h_en_ambig_cb", None, [
            "Hi, calling from admin cabin regarding Thursday inventory audit; call back when back at desk.",
            "Please ring this temporary intercom line regarding basement two-wheeler sticker pickup.",
            "Hello, texting about inverter battery service scheduled yesterday; return call after 4 PM.",
            "Ping me on this extension once you review the revised housing society maintenance note.",
        ]),
        ("english", None, "ambiguous_payment_reminder", "v7h_en_ambig_pay", None, [
            "Reminder that Rs. 1,450 toward this month's terrace solar panel cleaning pool falls due Friday.",
            "Hey, Rs. 420 shared station auto split from Saturday night remains due; settle whenever convenient.",
            "Badminton court quarterly badge renewal INR 750 can be settled at clubhouse reception before Monday.",
            "Study group spiral binding share Rs. 390 per student is payable prior to Wednesday seminar.",
        ]),
        ("english", None, "ambiguous_sparse_link", "v7h_en_ambig_link", None, [
            "Shared updated residents shuttle timetable and block circular on https://wing-board.example/shuttle.",
            "Carrom Sunday doubles knockout schedule uploaded at https://carrom-draw.example/sunday.",
            "View revised auditorium seating map and workshop slots on https://dept-hall.example/slots.",
            "Apartment rainwater drain inspection roster shared via https://civic-notice.example/roster.",
        ]),
        ("hinglish", None, "ambiguous_callback", "v7h_hi_ambig_cb", None, [
            "Bhaiya free hone par is mobile par wapas ring kar dena, budhwar annual lunch ke menu par baat karni thi.",
            "Hello, aapke scooter RC smart card ke papers office desk par rakhe hain; shaam ko callback kar lena.",
            "Zaroori charcha karni thi, library se nikal kar ek baar is alternate number par call milana.",
            "Side gate par tiffin packet rakha hai, lene ke liye security bhaiya ko phone kar lo.",
        ]),
        ("hinglish", None, "ambiguous_payment_reminder", "v7h_hi_ambig_pay", None, [
            "Society lift AMC servicing hissa Rs. 600 is Shukrawar tak treasurer room mein dene ka reminder hai.",
            "Kal raat ke dinner aur chai ke Rs. 340 hisaab baaki hain, time milne par transfer kar dena.",
            "Swimming pool summer pass renew karne ke Rs. 550 agle Mangalwar tak counter par jama kar dein.",
            "Picnic mini-bus seat advance Rs. 850 ka reminder—aaj shaam tak final list banani hai.",
        ]),
        ("hinglish", None, "ambiguous_sparse_link", "v7h_hi_ambig_link", None, [
            "Badminton Sunday league ka taja fixture https://court-match.example/sunday par daal diya gaya hai.",
            "Apartment solar heater cleaning schedule https://wing-notice.example/solar par dekh lein.",
            "Botany workshop ke handouts aur notes https://bio-notes.example/slides par mil jayenge.",
            "Hostel mess ka agle hafte ka nashta chart https://hostel-diet.example/menu par upload hua hai.",
        ]),
    ]

    rows = []
    idx = 1
    for lang, label, category, family, pair_id, texts in specs:
        for text in texts:
            row = {
                "id": f"v7h{idx:03d}",
                "label": label,
                "language": lang,
                "category": category,
                "family": family,
                "source": "synthetic_v7_holdout",
                "text": text,
            }
            if pair_id is not None:
                row["pair_id"] = pair_id
            rows.append(row)
            idx += 1
    return rows


def main() -> None:
    v6_dev = read_jsonl(ROOT / "data/synthetic/v6_development.jsonl")
    v7_add = _build_v7_development_additions()
    v7_dev = v6_dev + v7_add
    v7_hold = build_v7_holdout()

    ids_dev = set()
    for r in v7_dev:
        assert r.get("split") in ("train", "calibration", "validation")
        assert r.get("label") in (0, 1)
        assert r["id"] not in ids_dev, f"Duplicate id {r['id']}"
        ids_dev.add(r["id"])
        r["text"] = normalize_sms(r["text"])
    check_leakage(v7_dev)

    ids_hold = set()
    for r in v7_hold:
        assert r.get("label") in (0, 1, None)
        assert r["id"] not in ids_hold, f"Duplicate holdout id {r['id']}"
        ids_hold.add(r["id"])
        r["text"] = normalize_sms(r["text"])

    assert sum(1 for r in v7_hold if r["label"] in (0, 1)) == 240
    assert sum(1 for r in v7_hold if r["label"] is None) == 24
    assert sum(1 for r in v7_hold if r["language"] == "english" and r["label"] == 0) == 60
    assert sum(1 for r in v7_hold if r["language"] == "english" and r["label"] == 1) == 60
    assert sum(1 for r in v7_hold if r["language"] == "hinglish" and r["label"] == 0) == 60
    assert sum(1 for r in v7_hold if r["language"] == "hinglish" and r["label"] == 1) == 60

    dev_fams_by_split = {
        sp: {r["family"] for r in v7_dev if r["split"] == sp}
        for sp in ("train", "calibration", "validation")
    }
    hold_fams = {r["family"] for r in v7_hold}
    for i, a in enumerate(("train", "calibration", "validation")):
        assert not (dev_fams_by_split[a] & hold_fams), f"Family overlap {a} vs holdout"
        for b in ("train", "calibration", "validation")[i + 1:]:
            assert not (dev_fams_by_split[a] & dev_fams_by_split[b]), f"Family overlap {a} vs {b}"

    external_rows = []
    for tag, rel in (
        ("v6_hold", "data/synthetic/v6_holdout.jsonl"),
        ("v5_hold", "data/synthetic/v5_holdout.jsonl"),
        ("v4_hold", "data/synthetic/v4_holdout.jsonl"),
        ("v3_hold", "data/synthetic/v3_holdout.jsonl"),
        ("v2_hold", "data/synthetic/v2_holdout.jsonl"),
        ("indian", "data/synthetic/indian_sms.jsonl"),
        ("uci_train", "data/processed/train.jsonl"),
        ("uci_cal", "data/processed/calibration.jsonl"),
        ("uci_val", "data/processed/validation.jsonl"),
        ("uci_test", "data/processed/test.jsonl"),
    ):
        for r in read_jsonl(ROOT / rel):
            external_rows.append({"id": f"{tag}:{r['id']}", "partition": tag, "text": normalize_sms(r["text"])})
    for idx, txt in enumerate(REPRODUCED_BLACKLIST_TEXTS):
        external_rows.append({"id": f"repro:{idx}", "partition": "repro_blacklist", "text": normalize_sms(txt)})

    v7_hold_brands = (
        "chilika", "vaitarna", "tapti", "hampi", "mysuru", "saryu",
        "koyna", "bhima", "puri rail", "ladakh", "zuari", "rishikesh",
    )
    v6_hold_brands = (
        "tungabhadra", "sabarmati", "periyar", "konark", "vellore", "gomti",
        "sutlej", "beas", "nilachal", "zanskar", "mandovi", "shivalik",
    )
    v5_hold_brands = (
        "narmada", "vindhya", "satpura", "coromandel", "yamuna mart", "tapi express",
        "cauvery", "mahanadi", "sahyadri", "chinar", "brahmaputra", "aravalli",
    )
    v4_hold_brands = (
        "kaveri", "deccan", "nilgiri", "saffron", "malabar", "tamarind",
        "chambal", "konkan", "palash", "godavari",
    )
    dev_brands = (
        "harbor bank", "harbor", "solstice", "meridian", "evergreen", "crestline",
        "banyan coop", "banyan", "oakwood", "cedar", "pinnacle", "sunrise mart", "horizon", "metro grid", "metro",
    )

    v7_add_blob = " \n ".join(r["text"].lower() for r in v7_add)
    for b in v7_hold_brands + v6_hold_brands + v5_hold_brands + v4_hold_brands:
        assert b not in v7_add_blob, f"Leaked holdout entity {b!r} in V7 dev additions!"

    v7_hold_blob = " \n ".join(r["text"].lower() for r in v7_hold)
    for b in v6_hold_brands + v5_hold_brands + v4_hold_brands + dev_brands:
        assert b not in v7_hold_blob, f"Leaked dev/prior-hold entity {b!r} in V7 holdout!"

    dev_canon = {canonical(r["text"]): r for r in v7_dev}
    hold_canon = {canonical(r["text"]): r for r in v7_hold}
    ext_canon = {canonical(r["text"]): r for r in external_rows}
    assert not (set(dev_canon) & set(hold_canon)), "Exact canonical overlap V7 dev vs V7 holdout!"
    assert not (set(dev_canon) & set(ext_canon)), f"Exact canonical overlap V7 dev vs ext: {set(dev_canon) & set(ext_canon)}"
    assert not (set(hold_canon) & set(ext_canon)), f"Exact canonical overlap V7 hold vs ext: {set(hold_canon) & set(ext_canon)}"

    tagged = (
        [{"id": r["id"], "partition": f"dev:{r['split']}", "text": r["text"]} for r in v7_dev]
        + [{"id": r["id"], "partition": "v7_hold", "text": r["text"]} for r in v7_hold]
        + external_rows
    )
    groups = group_near_duplicates(tagged, similarity=0.85)
    bucket_parts: dict[int, list[tuple[str, str]]] = {}
    for item, g in zip(tagged, groups):
        bucket_parts.setdefault(g, []).append((item["partition"], item["id"]))

    cross_hits = []
    for g, items in bucket_parts.items():
        parts_set = {p for p, _ in items}
        ids = [item_id for _, item_id in items]
        if len(parts_set) > 1 and any(item_id.startswith(("v7h", "v7d")) for item_id in ids):
            cross_hits.append(items)

    assert not cross_hits, f"V7 cross-partition near-duplicate collisions (>=0.85): {cross_hits}"

    dev_out = ROOT / "data/synthetic/v7_development.jsonl"
    hold_out = ROOT / "data/synthetic/v7_holdout.jsonl"
    write_jsonl(dev_out, v7_dev)
    write_jsonl(hold_out, v7_hold)

    summary = {
        "v7_development_sha256": digest(dev_out),
        "v7_holdout_sha256": digest(hold_out),
        "v7_dev_total": len(v7_dev),
        "v7_add_count": len(v7_add),
        "v7_dev_counts": {
            sp: {
                "total": sum(r["split"] == sp for r in v7_dev),
                "label_0": sum(r["split"] == sp and r["label"] == 0 for r in v7_dev),
                "label_1": sum(r["split"] == sp and r["label"] == 1 for r in v7_dev),
                "english": sum(r["split"] == sp and r["language"] == "english" for r in v7_dev),
                "hinglish": sum(r["split"] == sp and r["language"] == "hinglish" for r in v7_dev),
            }
            for sp in ("train", "calibration", "validation")
        },
        "v7_holdout_counts": {
            "total": len(v7_hold),
            "labeled": sum(r["label"] in (0, 1) for r in v7_hold),
            "ambiguous": sum(r["label"] is None for r in v7_hold),
            "english_0": sum(r["language"] == "english" and r["label"] == 0 for r in v7_hold),
            "english_1": sum(r["language"] == "english" and r["label"] == 1 for r in v7_hold),
            "hinglish_0": sum(r["language"] == "hinglish" and r["label"] == 0 for r in v7_hold),
            "hinglish_1": sum(r["language"] == "hinglish" and r["label"] == 1 for r in v7_hold),
        },
        "near_dup_cross_partition_085_v7_hits": len(cross_hits),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
