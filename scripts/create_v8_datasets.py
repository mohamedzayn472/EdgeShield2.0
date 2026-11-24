"""Create strictly family-separated V8 synthetic development and fresh unseen V8 holdout datasets.

Preserves all V1-V7 datasets untouched. Enforces zero family overlap, zero exact text overlap,
entity firewalls across dev/V4/V5/V6/V7/V8 brands, and zero cross-partition char 3-5-gram
near-duplicates (>= 0.85 cosine similarity) across V8 dev splits, V8 holdout, V7 holdout,
V6 holdout, V5 holdout, V4 holdout, V3 holdout, V2 holdout, indian_sms, UCI processed splits,
and reproduced failure strings.
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


def _build_v8_development_additions() -> list[dict]:
    """Preserve the balanced 1,018-row V7 development corpus untouched for V8 classifier training."""
    return []


def build_v8_holdout() -> list[dict]:
    """Build fresh unseen 240 labeled (120 EN, 120 HI) + 24 ambiguous holdout messages.

    Uses 100% fresh unseen entities: Pench Bank, Hemavati Trust, Sharavathi Pay, Ellora Card,
    Udupi Mart, Betwa Express, Idukki Power, Teesta Water, Dwaraka Rail, Spiti Telecom,
    Netravati Fin, Kasauli Hospital.
    """
    specs = [
        # ==================== ENGLISH BENIGN (60 = 10 categories x 6) ====================
        ("english", 0, "otp_delivery", "v8h_en_otp", "ctrl8_otp_1", [
            "Pench Bank single-use OTP 539184 generated to view your annual tax summary. Keep these six digits strictly private.",
            "Hemavati Trust alert: Temporary code 762049 issued for INR 1,520.00 purchase at Udupi Mart. Never disclose to any caller.",
            "Sharavathi Pay preferences: Enter passcode 481930 strictly inside our official mobile banking screen to register water biller.",
            "714820 is your login code for Ellora Card controls inside Hemavati netbanking. Support staff never phone for codes.",
            "Kasauli Hospital billing OTP 829104 remains active for five minutes on Sharavathi checkout. Do not read aloud to anyone.",
            "Pench verification: Key in temporary passcode 650318 within your logged-in application screen to approve Idukki utility mandate.",
        ]),
        ("english", 0, "fraud_awareness", "v8h_en_awareness", None, [
            "Pench Bank Security Bulletin: Swindlers circulate fake debit freeze notices and clone KYC links. Staff never ask for passwords or PINs.",
            "Hemavati Digital Hygiene Alert: Do not click short web URLs urging sudden e-KYC upload; open your official banking app directly.",
            "Ellora Card Caution Note: Disregard messages pushing instant web-link verification; representatives never ask patrons to speak digits aloud.",
            "Sharavathi Pay Safety Tip: Tricksters send payment collect prompts disguised as prize payouts; no PIN is required to receive funds.",
            "Netravati Fin cyber advisory: Impostors spoof helpline numbers alleging locked accounts. Refuse screen-sharing apps and hang up promptly.",
            "Pench customer reminder: Check unexpected debit warnings inside your app ledger instead of dictating SMS passcodes on voice calls.",
        ]),
        ("english", 0, "debit_credit_receipt", "v8h_en_tx_receipt", None, [
            "Pench Bank: Savings A/c XX5281 credited with INR 24,600.00 via NEFT Ref PB7739201. Available balance INR 68,920.00.",
            "Hemavati Trust: Debit of Rs. 1,460.00 noted on A/c XX6419 at Udupi Mart on 24-Nov-26. Call 1800-600-8833 if unfamiliar.",
            "Ellora Credit Card XX3108 spent INR 2,340.00 at Betwa Express Cargo on 23-Nov-26. Remaining credit limit Rs. 91,200.00.",
            "Monthly salary credit: Account ending 5281 with Pench Bank received INR 51,000.00 via IMPS Ref 884019283746.",
            "Rail booking receipt: Dwaraka Rail fare Rs. 975.00 paid with Hemavati debit card XX9042 on 23-Nov-26.",
            "Savings interest credit: Netravati Fin deposited INR 534.80 quarterly yield straight into account XX4716.",
        ]),
        ("english", 0, "failed_payment_reversal", "v8h_en_reversal", "ctrl8_refund_1", [
            "Pench Settlement: Failed Udupi Mart debit of Rs. 1,310.00 was reversed cleanly into A/c XX5281 with no further action.",
            "Hemavati Auto-Refund: Declined Dwaraka Rail ticket charge INR 1,120.00 returned to savings balance; no approval code needed.",
            "Sharavathi Pay reversal note: Unsuccessful UPI payment of INR 1,790.00 credited back automatically to your linked account.",
            "Udupi Mart order refund: Rs. 910.00 for canceled grocery basket settled directly back to card ending 6419.",
            "Betwa Express reimbursement: INR 1,480.00 for voided waybill posted into Pench savings A/c XX5281.",
            "Ellora Card billing update: Duplicate POS pre-auth of Rs. 2,960.00 dropped off statement balance automatically without calling support.",
        ]),
        ("english", 0, "user_card_block", "v8h_en_user_block", "ctrl8_block_1", [
            "Pench Bank confirmation: Your manual in-app block request on debit card XX9042 took effect cleanly with no follow-up needed.",
            "Hemavati Trust: As initiated by your mobile session, ATM card XX6419 has been disabled; request a replacement inside Card Controls.",
            "Sharavathi Card settings: You paused tap-and-pay and locked card XX3108 via app controls; unpause anytime yourself.",
            "Netravati Fin confirmation: Missing debit card XX4716 locked per your phone request; replacement card ships in five days.",
            "Ellora Card notice: Self-initiated freeze request on card ending 3108 succeeded cleanly inside mobile banking.",
            "Hemavati record: Customer-initiated card pause on ending 5281 completed; staff never call asking for PINs to unlock.",
        ]),
        ("english", 0, "branch_kyc_appointment", "v8h_en_branch_kyc", None, [
            "Pench Branch Desk: Routine KYC renewal appointment at Shimla Mall branch is confirmed for 18-Dec-26 at 10:45 AM.",
            "Hemavati Trust confirmation: Submitted KYC forms at Kochi Harbor branch passed check cleanly with nothing pending.",
            "Ellora Card desk: Thank you for visiting Jayanagar branch; your identity documents were reviewed and marked current.",
            "Netravati Fin booking: Counter slot #08 at Bhopal Civil branch is reserved for your scheduled annual KYC review on 19-Dec-26.",
            "Sharavathi Trust reminder: Your counter appointment for periodic Know Your Customer verification is booked on 20-Dec-26 at 11:30 AM; bring original ID.",
            "Pench completion note: Periodic KYC review lodged at local branch counter finished verification properly.",
        ]),
        ("english", 0, "statement_notification", "v8h_en_statement", None, [
            "Pench Bank monthly PDF: November passbook statement for A/c XX5281 is ready at https://docs.penchbank.example/statements/nov.",
            "Hemavati e-statement: View your quarterly savings ledger online at https://portal.hemavati.example/passbook.",
            "Ellora Card cycle statement: Monthly bill for XX3108 archived securely at https://billing.elloracard.example/invoice.",
            "Netravati Fin annual note: Interest summary and TDS sheet available at https://archive.netravatifin.example/tds.",
            "Spiti Telecom invoice: Monthly bill #ST82910 for Rs. 579.00 published at https://bills.spititel.example/pdf.",
            "Sharavathi savings document: Half-yearly fee schedule uploaded to https://docs.sharavathipay.example/fees.",
        ]),
        ("english", 0, "upi_notification", "v8h_en_upi", None, [
            "Sharavathi Pay alert: Transferred INR 680.00 from Pench A/c XX5281 to Kasauli Hospital Pharmacy. Ref 553019283746.",
            "Via Hemavati UPI rail: Received INR 1,640.00 directly into savings account ending 6419 (UTR 774029384711).",
            "Paid Rs. 710.00 cleanly using Sharavathi handle to Teesta Water Supply on 24-Nov-26. Ref #662918374650.",
            "Pench UPI credit: Rs. 2,540.00 received from A. Deshmukh into XX5281. Check updated balance inside official app.",
            "Power bill UPI receipt: Idukki Power received INR 1,510.00 smoothly via Txn Ref 992019384756.",
            "Recurring auto-debit: Spiti Telecom monthly Rs. 379.00 plan settled cleanly from Hemavati A/c XX6419.",
        ]),
        ("english", 0, "balance_notification", "v8h_en_balance", None, [
            "Pench savings balance: Cleared balance in A/c XX5281 at close of 24-Nov-26 stands at INR 68,920.00.",
            "Hemavati balance update: Checking A/c XX6419 holds Rs. 31,750.00 available cash as of morning sync.",
            "Ellora Card headroom: Unspent credit limit on XX3108 sits at Rs. 91,200.00 against Rs. 1,15,000.00 total limit.",
            "Netravati Fin flexi-line report: Active overdraft borrowing stands at INR 0.00 with full INR 48,000.00 reserve untouched.",
            "Sharavathi Pay ledger: Available wallet balance equals INR 3,840.00 inside mobile app dashboard.",
            "Pench account XX5281 snapshot: Cleared funds INR 21,300.00 with zero pending holds.",
        ]),
        ("english", 0, "delivery_utility_benign", "v8h_en_utility", None, [
            "Udupi Mart order #UM91042 shipped via Betwa Express and arrives tomorrow evening; track status in shopping app.",
            "Idukki Power confirmation: Payment of Rs. 1,690.00 credited to Consumer #IP64019. Next meter reading on 24-Dec-26.",
            "Kasauli Hospital front desk: Dental consultation booked Saturday 03:30 PM with Dr. Mehta; bring previous X-ray film.",
            "Teesta Water receipt: Monthly water bill Rs. 395.00 cleared cleanly for Account TW40812. Zero balance due.",
            "Dwaraka Rail update: Coach A2 Seat 14 confirmed on Express 19504 departing Friday 06:50 AM.",
            "Spiti Telecom alert: Monthly 48 GB mobile data pack renewed cleanly for next 28-day cycle.",
        ]),

        # ==================== ENGLISH SCAM (60 = 10 categories x 6) ====================
        ("english", 1, "account_block_threat", "v8h_en_block", "ctrl8_block_1", [
            "URGENT Pench Bank alert: Your savings account suspends at midnight! Click https://bit.ly/pench-unlock immediately to verify identity.",
            "Hemavati security warning: Debit card XX6419 blocked after suspicious login! Sign in at https://hemavati-unblock.example right now to avoid closure.",
            "Ellora Card emergency: Credit limit freezes permanently in 2 hours unless reactivated at https://t.co/ellora-verify.",
            "Netravati Fin security hold: Transfers on A/c XX4716 are suspended! Text back your 16-digit card number and CVV immediately to reopen.",
            "Sharavathi Pay freeze notice: Your wallet closes permanently at 11 PM unless you re-enter login credentials on https://tinyurl.com/sharavathi-fix.",
            "Pench card alert: ATM withdrawals temporarily frozen! Text back PIN and expiry date right now to unblock.",
        ]),
        ("english", 1, "otp_pin_solicitation", "v8h_en_otp", "ctrl8_otp_1", [
            "Pench Fraud Desk: Send your 6-digit OTP right now so our officer cancels an unauthorized Rs. 6,400.00 debit.",
            "Hemavati vigilance unit: Reply immediately with ATM PIN and CVV to reverse a rogue international swipe.",
            "Ellora Support team: Message back 4-digit MPIN along with verification code urgently to stop reward points expiry.",
            "Always keep passwords private from strangers. However, send your 6-digit OTP right now to process your fee refund.",
            "Sharavathi Helpdesk: Forward the 6-digit SMS security token right away to unlock higher wallet transfer limits.",
            "Security rules say never share PINs; still, reply with your verification OTP immediately to claim pending cashback.",
        ]),
        ("english", 1, "fake_kyc_link", "v8h_en_kyc", None, [
            "Pench customer alert: KYC compliance expired! Visit https://bit.ly/pench-kyc within two hours or netbanking shuts off.",
            "Hemavati e-KYC warning: Submit Aadhaar and PAN details via https://hemavati-ekyc.example right away to avoid account freeze.",
            "Ellora Credit notice: Re-verify KYC records urgently at https://tinyurl.com/ellora-kyc or card deactivates tonight.",
            "Netravati KYC portal: Enter login password and PAN number immediately at https://netravati-kyc.example to keep transfers active.",
            "Sharavathi Trust alert: Re-KYC check failed; tap https://rb.gy/sharavathi-kyc immediately so incoming credits are not blocked.",
            "Pench compliance emergency: Complete KYC verification tonight urgently or online banking closes permanently at midnight.",
        ]),
        ("english", 1, "fake_refund", "v8h_en_refund", "ctrl8_refund_1", [
            "Udupi Mart refund ready: Approve incoming collect request for INR 1,310 right now inside UPI app to credit A/c XX5281.",
            "Betwa Express delay rebate Rs. 2,250 sanctioned: Accept pending collect popup immediately and enter UPI PIN.",
            "Idukki Power double-billing refund INR 1,690 queued! Confirm payment collect prompt on Sharavathi Pay with PIN to receive funds.",
            "Ellora annual fee waiver Rs. 999 approved—tap Authorize on our incoming collect notification immediately for credit.",
            "Never disclose secrets to callers; however, accept this Rs. 1,750 collect request right now to settle excess charge.",
            "Dwaraka Rail cancelled ticket refund INR 1,380 cleared: Approve payment collect request promptly to pull money into savings.",
        ]),
        ("english", 1, "read_aloud_otp", "v8h_en_read_aloud", None, [
            "Billing desk calling: Rs. 3,799 annual card fee hits Ellora Card today. Speak the 6-digit cancellation code aloud on call right now.",
            "Pench security unit: We sent an abort passcode to stop rogue transfer. Read out every digit of that security code aloud now.",
            "Dispute helpdesk calling: Dictate the single-use reversal code just texted so we halt an INR 4,800 debit.",
            "Refund verification agent regarding Rs. 2,750 wrong charge: Read aloud the SMS security code over the phone immediately.",
            "Auto-debit stop team: Card bills Rs. 1,950 in 5 minutes—speak out the confirmation code delivered to inbox aloud right now.",
            "Safety rules advise hiding PINs, yet dictate your 6-digit abort OTP aloud on this call right now to prevent theft.",
        ]),
        ("english", 1, "family_transfer_urgent", "v8h_en_family", None, [
            "Hey bro stranded near highway toll plaza with dead battery using guard's hotspot. Transfer 3,900 rs via UPI right away, call drops here.",
            "Mom my regular SIM stopped working in heavy rain and I need INR 7,600 wired urgently for hospital counter; do not call back, 1 percent battery.",
            "Dad texting from lab partner's phone because mine cracked outside hostel. Send Rs. 5,700 urgently via Sharavathi UPI right now, mic is broken.",
            "Auntie lost my primary handset at railway gate and borrowing kiosk phone. Kindly wire INR 4,500 immediately to this UPI ID, cannot take voice calls.",
            "Sis urgent—my SIM card failed outstation and texting from driver's phone. Transfer Rs. 5,200 right now to this QR handle, talk once home.",
            "Ma borrowing colleague's handset after mine blacked out at terminal. Please send INR 6,700 urgently via UPI for ticket payment, do not ring this line.",
        ]),
        ("english", 1, "delivery_customs_scam", "v8h_en_delivery", None, [
            "Betwa Express Customs alert: Overseas parcel detained at cargo hub; pay INR 670 duty at https://bit.ly/betwa-duty before auction.",
            "Udupi Dispatch notice: Street number missing on parcel #UD7041—update address and pay Rs. 42 redelivery fee via https://betwa-rebook.example now.",
            "Urgent customs detention notice: Shipment returns tonight! Clear INR 860 import tax at https://tinyurl.com/hub-duty right away.",
            "Cargo depot warning: Unpaid demurrage fee Rs. 510 overdue on consignment; remit via https://rb.gy/hub-fee before 5:30 PM.",
            "Final delivery notice from Betwa Courier: Confirm postal PIN and pay INR 275 reroute fee at https://betwa-ship.example immediately.",
            "Import compliance hold: Parcel blocked over missing KYC—upload ID and Rs. 740 fee via https://cargo-customs.example urgently.",
        ]),
        ("english", 1, "prize_lottery_scam", "v8h_en_prize", None, [
            "WINNER NOTICE! Your mobile won Pench Grand Lucky Draw INR 6,80,000! Claim immediately at https://bit.ly/pench-prize.",
            "Sharavathi Festive Draw: Selected winner of Rs. 48,000 shopping voucher + phone! Pay Rs. 499 courier charge at https://sharavathi-claim.example.",
            "Ellora Card Cashback Jackpot: INR 34,000 reward expires midnight—open https://tinyurl.com/ellora-cash and verify card CVV.",
            "Spiti Telecom Lucky Draw: You won laptop + Rs. 1,20,000 cash! Settle processing fee right away via https://t.co/spiti-win.",
            "Hemavati Mega Raffle: INR 2,10,000 payout waiting under your number—enter A/c details and Rs. 999 GST at https://hemavati-win.example.",
            "Festive reward INR 17,500 unlocked inside Sharavathi Wallet! Submit UPI PIN at https://rb.gy/fest-reward today.",
        ]),
        ("english", 1, "job_scam", "v8h_en_job", None, [
            "Remote item rating part-time opening! No experience needed, earn INR 3,700 daily via Telegram desk—join now with Rs. 950 onboarding deposit.",
            "Work-from-home merchant review vacancy: Make Rs. 2,700–4,700 daily! Message Telegram manager immediately and pay Rs. 760 slot fee.",
            "Online app testing job hiring today! Guaranteed Rs. 3,300 daily payout; visit https://bit.ly/work-kit to buy starter pass.",
            "Hiring smartphone ad-click associates right now! Collect INR 4,100 per day; message our Telegram recruiter and deposit Rs. 899 activation charge.",
            "Hotel booking portal hiring freelance reviewers! Daily earnings Rs. 3,800; send Rs. 1,080 kit deposit via https://tinyurl.com/task-pass.",
            "Immediate data tagging assistant hiring at Udupi Partner Desk! Earn Rs. 2,950 daily; transfer Rs. 680 security deposit to unlock tasks.",
        ]),
        ("english", 1, "utility_disconnect_scam", "v8h_en_utility_scam", None, [
            "URGENT Idukki Power notice: Domestic electricity cuts off tonight at 9:30 PM over unverified previous bill. Call engineer 9811554433 immediately.",
            "Teesta Water shutoff warning: Household tap supply disconnects today—update bill receipt at https://bit.ly/teesta-stay right away.",
            "Idukki Power Board Alert: Smart meter suspension scheduled tonight; share UPI PIN or support token with officer 9700554433 right now.",
            "DISCONNECT WARNING from Power Office: Previous bill missing ledger update! Open https://tinyurl.com/idukki-cut immediately to stop disconnection.",
            "Spiti Telecom barring alert: Primary SIM deactivates permanently within 3 hours! Call supervisor 9822334411 urgently.",
            "Electricity grid disconnection alert: Pay INR 18 arrears reconciliation fee right now at https://rb.gy/grid-stay to stop midnight power cut.",
        ]),

        # ==================== HINGLISH BENIGN (60 = 10 categories x 6) ====================
        ("hinglish", 0, "otp_delivery", "v8h_hi_otp", "ctrl8_hi_otp_1", [
            "Sharavathi Wallet login verify karne ke liye 582910 one-time code bheja gaya hai; kisi caller ko bol kar ya SMS se na batayein.",
            "Hemavati Trust netbanking session ka suraksha OTP 749201 hai; koi bank adhikari ban kar pooche tab bhi mat dena.",
            "Udupi Mart par INR 1,460.00 payment ke liye Ellora SMS code 610492 jaari hua hai. Apna passcode aur PIN hamesha gupt rakhein.",
            "Kasauli Hospital bill INR 870.00 bharne ke liye OTP 439182 apni app screen par daalein; yeh code kisi ko forward mat karo.",
            "Pench Bank mein naya beneficiary jodne ka gopniya OTP 891204 hai; phone par kisi anjaan vyakti ko hargiz na batayein.",
            "Idukki bijli bill Rs. 820.00 jama karne ke liye Sharavathi verification OTP 374910 aaya hai; call karne walon ko kabhi na batayein.",
        ]),
        ("hinglish", 0, "fraud_awareness", "v8h_hi_awareness", None, [
            "Sharavathi Pay savdhani: Khate mein paisa receive hote waqt UPI PIN dalna ya collect prompt accept karna kabhi zaroori nahi hota.",
            "Pench Bank jaagrukta: Koi caller galat katoti wapas dilane ke bahane mobile par aaya code sunane ko kahe to turant phone rakh dein.",
            "Hemavati Trust niyam: Apna netbanking password aur 6-digit OTP hamesha niji rakhein; bank staff call karke KYC kabhi nahi poochta.",
            "Ellora cyber suraksha: Anjaan chhote URL khol kar e-KYC verify karne ke lalach se bachein; asli update official app mein dekhein.",
            "Netravati Fin savdhani: Kisi anjaan caller ke bolne par screen mirroring app phone mein na daalein aur inaam pane hetu MPIN mat bharein.",
            "Grahak suraksha sandesh: Khata block hone ke nakli SMS ya farzi call par vishwas na karein; official helpline par khud confirm karein.",
        ]),
        ("hinglish", 0, "debit_credit_receipt", "v8h_hi_tx_receipt", None, [
            "Pench Bank update: Savings khata XX5281 mein NEFT Ref PB7739201 dwara Rs. 18,200.00 jama hue. Uplabdh balance INR 68,920.00 hai.",
            "Hemavati Trust: Debit card XX6419 se Udupi Mart par Rs. 1,460.00 kharch darj hue; anjaan lenden hone par app mein report karein.",
            "Ellora Card XX3108 dwara Betwa Express par INR 2,340.00 ka bhugtan safal raha. Baki credit limit Rs. 91,200.00 hai.",
            "Netravati savings khate mein aaj Rs. 6,400.00 credit hue (IMPS Ref 884019283746); poora vivran mobile passbook mein dekhein.",
            "Kasauli Pharmacy par Hemavati debit card XX9042 se Rs. 890.00 kate gaye; sahayata ke liye 1800-600-8833 par call karein.",
            "Pench savings A/c XX5281 mein taimahi byaj ke Rs. 534.80 seedhe jama kar diye gaye hain.",
        ]),
        ("hinglish", 0, "failed_payment_reversal", "v8h_hi_reversal", "ctrl8_hi_refund_1", [
            "Sharavathi Pay auto-refund: Fail hui Rs. 1,310.00 ki rashi bina kisi PIN ya approval ke aapke Pench khate mein wapas aa gayi hai.",
            "Udupi Mart cancel order ke Rs. 910.00 seedhe Hemavati savings account mein jama ho gaye hain, UPI PIN daalne ki zaroorat nahi.",
            "Dwaraka Rail ticket radd hone par kata hua Rs. 1,120.00 balance mein wapas credit ho chuka hai; kisi link par click na karein.",
            "Ellora Card par do baar kati rashi Rs. 2,960.00 aapke agle statement mein automatically adjust ho gayi hai.",
            "Idukki bijli payment fail hone se Rs. 1,510.00 khud wapas Pench khata ending 5281 mein deposit ho gaye hain.",
            "Betwa parcel booking radd hone ka refund Rs. 1,480.00 aapke linked source account mein wapas aa chuka hai.",
        ]),
        ("hinglish", 0, "user_card_block", "v8h_hi_user_block", "ctrl8_hi_block_1", [
            "Pench mobile app mein aapne khud apna debit card XX9042 lock kar diya hai; anjaan hone par 1800-600-8833 par sampark karein.",
            "Hemavati Trust soochna: Aapke nirdesh ke anusar ATM card XX6419 permanently disable kar diya gaya hai.",
            "Sharavathi Card update: App ke security menu se aapne card XX3108 par videshi aur POS tap transaction khud freeze kar diye hain.",
            "Card kho jaane par aapki request se Netravati debit card XX4716 block ho gaya hai; replacement card 5 din mein pahunchega.",
            "Ellora Card record: Mobile banking toggle dwara aapne apna card XX3108 kuch samay ke liye lock kiya hai; zaroorat par khud kholein.",
            "Hemavati portal par aapke dwara debit card ending 5281 band kar diya gaya hai; dobara chalu karne branch ya app control dekhein.",
        ]),
        ("hinglish", 0, "branch_kyc_appointment", "v8h_hi_branch_kyc", None, [
            "Hemavati Desk: Kochi shakha counter par jama ki gayi aapki saalana KYC file verify aur approve ho chuki hai.",
            "Pench Bank soochna: Shimla Mall branch mein aapki routine KYC check meeting 18-Dec subah 10:45 AM fix hui hai.",
            "Ellora Counter Update: Branch mein aapne jo ID proof aur KYC kagaz diye unka verification poorn hokar record current mark ho gaya.",
            "Netravati Fin branch desk: Bhopal Civil branch counter #08 par annual KYC review ke liye aapka Somwar ka slot book hua hai.",
            "Sharavathi Trust: Branch counter par jama aapki periodic KYC verification safaltapoorvak samaapt ho gayi hai, reply ki zaroorat nahi.",
            "Pench reminder: Shimla branch counter par kal dopahar verification ke samay apna original photo ID saath laayein.",
        ]),
        ("hinglish", 0, "statement_notification", "v8h_hi_statement", None, [
            "Pench savings khata XX5281 ka November maah ka PDF statement https://docs.penchbank.example/nov par dekha ja sakta hai.",
            "Sharavathi Pay aur linked account ki maasik transaction report https://reports.sharavathipay.example/ledger par uplabdh hai.",
            "Hemavati Trust taimahi passbook aur interest sheet download karne ke liye https://portal.hemavati.example/passbook dekhein.",
            "Ellora Card XX3108 ka naya billing summary aur PDF invoice https://billing.elloracard.example/nov-pdf par upload ho gaya hai.",
            "Netravati savings khate ka annual TDS certificate https://archive.netravatifin.example/tds par download hetu taiyar hai.",
            "Spiti Telecom postpaid plan ka monthly bill PDF https://bills.spititel.example/monthly par check karein.",
        ]),
        ("hinglish", 0, "upi_notification", "v8h_hi_upi", None, [
            "Sharavathi UPI update: Kasauli Medical Store ko Rs. 680.00 bheje gaye aur UPI Ref 553019283746 darj hua.",
            "Hemavati khata ending 6419 mein Pench UPI se Rs. 1,640.00 credit ho gaye hain (UTR 774029384711).",
            "Idukki Power bijli bill ke Rs. 1,690.00 Sharavathi UPI (Ref 992019384756) se safaltapoorvak jama ho chuke hain.",
            "Udupi Mart par Hemavati QR scan karke Rs. 830.00 ka payment poora raha; naya balance app mein dekhein.",
            "Aapke Pench A/c XX5281 se Kulkarni ji ko UPI dwara Rs. 970.00 bheje gaye aur ledger update ho gaya.",
            "Teesta Jal board bill ke Rs. 395.00 Sharavathi UPI se jama kar diye gaye hain (Ref 662918374650).",
        ]),
        ("hinglish", 0, "balance_notification", "v8h_hi_balance", None, [
            "Pench savings A/c XX5281 mein aaj shaam uplabdh balance INR 68,920.00 darj hua hai aur hold rashi shunya hai.",
            "Hemavati Trust khata XX6419 ka taja clear balance subah sync ke baad Rs. 31,750.00 hai.",
            "Ellora Card XX3108 par abhi Rs. 91,200.00 ki kharch seema shesh hai; agla bill 16-Dec ko banega.",
            "Sharavathi Pay wallet aur jude savings khate ka kul clear balance INR 3,840.00 app par uplabdh hai.",
            "Netravati account XX4716 mein bina kisi pending cheque ke Rs. 21,300.00 safe aur uplabdh hain.",
            "Pench deposit aur savings khata vivran aaj subah aapke mobile banking ledger mein update ho chuka hai.",
        ]),
        ("hinglish", 0, "delivery_utility_benign", "v8h_hi_utility", None, [
            "Udupi Mart se aapka order Betwa Express courier dwara nikal chuka hai aur kal shaam tak ghar pahunchega.",
            "Idukki bijli board: Consumer IP64019 par Rs. 1,690.00 jama ho gaye hain, agla meter bill 24-Dec ko aayega.",
            "Kasauli Hospital reception: Shanivar dopahar 03:30 PM Dr. Mehta ke saath checkup tay hai, purani reports saath rakhein.",
            "Teesta Water bill Rs. 395.00 poori tarah jama ho chuka hai aur khate par koi bakaya nahi hai.",
            "Spiti Telecom mobile pack: Aapka 48 GB data aur calling plan agle 28 din ke liye chalu ho gaya hai.",
            "Dwaraka Rail ticket soochna: Shukrawar subah 06:50 AM gaadi 19504 mein Coach A2 Seat 14 confirm ho gayi hai.",
        ]),

        # ==================== HINGLISH SCAM (60 = 10 categories x 6) ====================
        ("hinglish", 1, "account_block_threat", "v8h_hi_block", "ctrl8_hi_block_1", [
            "Pench urgent warning: Aaj raat 11:30 baje aapka savings khata freeze ho jayega! Turant https://bit.ly/pench-block khol kar KYC karein.",
            "Hemavati ATM alert: Card XX6419 sandigdh login se block ho raha hai, https://hemavati-unlock.example par abhi card details bharo.",
            "Ellora Credit Card agle 2 ghante mein band hone wala hai! https://t.co/ellora-kyc par turant MPIN verify karein.",
            "Sharavathi wallet suraksha alert: Khatre ke kaaran khata aaj block hoga, https://tinyurl.com/sharavathi-unfreeze par turant PIN confirm karein.",
            "Netravati bank khata alert: Account suspend hone se rokne ke liye abhi SMS reply mein full card number aur CVV bhejein.",
            "Pench netbanking aaj raat hamesha ke liye band ho rahi hai! Chalu rakhne helpline 9811554433 par turant ATM PIN batayein.",
        ]),
        ("hinglish", 1, "otp_pin_solicitation", "v8h_hi_otp", "ctrl8_hi_otp_1", [
            "Pench fraud desk: Aapke khate se Rs. 6,400 katne ja rahe hain, rokne ke liye abhi aaya 6-digit OTP turant reply karein.",
            "Hemavati card care: Galat merchant charge cancel karwane ke liye apna ATM PIN aur CVV turant message mein bhej do.",
            "Ellora helpdesk se bol raha hoon: Credit limit badhane hetu mobile par aaya OTP aur janm-tareekh abhi send karo.",
            "Bank niyam kehte hain password chhupayein, par Rs. 3,100 festive bonus lene ke liye SMS OTP abhi reply karein.",
            "Sharavathi support team: Wallet limit update poori karne phone par mila verification OTP aur MPIN turant likh kar bhejein.",
            "Advisories bolti hain code kisi ko na dein, lekin atka cashback turant khate mein dalwane apna verification OTP forward karo.",
        ]),
        ("hinglish", 1, "fake_kyc_link", "v8h_hi_kyc", None, [
            "Hemavati urgent compliance alert: Aaj raat se pehle digital KYC re-verification na hone par aapka bank portal aur UPI seva rok di jayegi.",
            "Pench e-KYC antim alert: Turant https://bit.ly/pench-ekyc khol kar PAN upload karein warna khata hamesha ke liye freeze hoga.",
            "Ellora PAN record adhoora hai! https://tinyurl.com/ellora-pan par abhi details bharein nahi to debit aur credit card block hoga.",
            "Netravati KYC portal: Shaam 6 baje tak https://netravati-ekyc.example par login aur Aadhaar number submit karo warna paisa rukega.",
            "Sharavathi e-KYC error: Wallet verification fail ho gaya; payments chalu rakhne https://rb.gy/sharavathi-kyc par abhi verify karein.",
            "Pench compliance desk: Emergency KYC aaj samapt ho rahi hai, block se bachne SMS reply mein card number aur PIN bhejo.",
        ]),
        ("hinglish", 1, "fake_refund", "v8h_hi_refund", "ctrl8_hi_refund_1", [
            "Udupi Mart refund pass ho gaya: Rs. 1,310 khate mein wapas lene Sharavathi UPI par aayi collect request abhi approve karein aur PIN daalein.",
            "Betwa Express delay refund Rs. 2,250 pane ke liye mobile par aayi payment collect request accept karke PIN confirm karein.",
            "Kasauli Hospital mein double kate Rs. 1,690 wapas lene abhi aayi collect notification accept karke UPI PIN bhar dein.",
            "Ellora membership shulk Rs. 999 ki wapsi khate mein pane hetu bheje gaye payment collect alert ko turant accept karke PIN bharein.",
            "Spiti recharge cashback Rs. 1,180 sidhe khate mein pane bheji gayi UPI collect request abhi accept karein.",
            "Secret PIN kisi ko mat batana, magar Rs. 2,450 refund lene ke liye incoming collect prompt par turant approve dabao.",
        ]),
        ("hinglish", 1, "read_aloud_otp", "v8h_hi_read_aloud", None, [
            "Ellora Card billing desk bol rahi hoon, aaj Rs. 3,799 annual charge kat raha hai; rokne ke liye SMS wala code abhi padh kar sunao.",
            "Pench security center: Card par Rs. 4,800 ka videshi swipe laga hai, cancel karne mobile par aaya OTP turant bol kar suna dein.",
            "Dwaraka Rail cancellation ke Rs. 1,850 wapas dilane phone par bheja gaya security token bina ruke call par padh kar batayein.",
            "Club membership fee Rs. 2,250 aaj automatically kategi; band karwane SMS se mila 6-digit code phone par bol kar batao.",
            "Netravati khate se galat insurance shulk Rs. 2,799 hatane ke liye inbox wala verification code abhi dictate karo.",
            "Pench suraksha niyam bolta hai password gupt rakho, phir bhi atka refund khate mein pane call par SMS token padh kar suna dein.",
        ]),
        ("hinglish", 1, "family_transfer_urgent", "v8h_hi_family", None, [
            "Bhaiya toll gate par gaadi phans gayi, mera phone band hai aur guard ka hotspot lekar likh raha. Abhi Rs. 3,900 UPI bhej do.",
            "Maa baarish mein mera phone aur SIM kharab ho gaya; hospital counter par dene abhi Rs. 7,600 transfer kar do, battery 1% hai call mat karna.",
            "Papa dost ke doosre number se msg kar raha kyunki mera handset station par gir ke toot gaya. Fees ke liye abhi Rs. 8,100 UPI send karo.",
            "Didi mera mobile screen toot gaya aur mic band pada hai. Dawai lene abhi Rs. 4,500 is QR handle par bhejo, ghar aakar deta hoon.",
            "Chacha wallet aur phone market mein chori ho gaya, dukan wale ke number se likh raha. Jaldi Rs. 5,200 is UPI par bhejo, call mat lagana.",
            "Mummy platform par khada hoon aur mera handset dead ho gaya; conductor ke mobile se text kiya hai, ticket hetu turant Rs. 6,300 UPI karo.",
        ]),
        ("hinglish", 1, "delivery_customs_scam", "v8h_hi_delivery", None, [
            "Betwa Express customs alert: Videsh se aaya parcel cargo port par ruka hai; aaj Rs. 670 duty https://bit.ly/betwa-duty par bharo.",
            "Udupi courier notice: Pata adhoora hone se packet hold par hai; https://betwa-track.example khol kar Rs. 42 redelivery shulk jama karein.",
            "Betwa Logistics antim warning: Aaj shaam aapka parcel wapas bhej diya jayega! Turant https://tinyurl.com/betwa-clear par address verify karo.",
            "Pench cargo import tax Rs. 860 baki hone se parcel zapt ho raha hai; turant https://rb.gy/hub-pay khol kar card se bhugtan karo.",
            "Betwa delivery agent ko ghar ka pata nahi mila; GPS pin update karne aur Rs. 155 dene https://udupi-ship.example link kholein.",
            "International gift box release karwane hetu Betwa customs fee Rs. 960 turant https://t.co/hub-gift par online bhugtan karein.",
        ]),
        ("hinglish", 1, "prize_lottery_scam", "v8h_hi_prize", None, [
            "DHAMAKA! Aapke mobile number ne Pench Mega Draw mein Rs. 6,80,000 jackpot jeeta hai! Claim karne https://bit.ly/pench-win turant kholein.",
            "Sharavathi festive draw mein aapko Rs. 48,000 + smart TV inaam nikla! Delivery ke liye Rs. 499 fee https://sharavathi-draw.example par bharo.",
            "Ellora reward draw winner: Aapko Rs. 34,000 cash reward mila—khate mein lene https://tinyurl.com/ellora-inaam par card aur CVV daalein.",
            "Spiti Telecom lucky draw mein laptop aur Rs. 1,20,000 jeete! Claim karne Rs. 899 GST fee https://t.co/spiti-inaam par turant jama karein.",
            "Hemavati Bumper Jackpot Rs. 2,10,000 aaj raat lapse hoga; bank A/c aur PIN https://hemavati-lotto.example par abhi verify karein.",
            "Sharavathi Diwali bonus Rs. 17,500 sidhe khate mein pane https://rb.gy/sharavathi-spin khol kar UPI PIN enter karo.",
        ]),
        ("hinglish", 1, "job_scam", "v8h_hi_job", None, [
            "Ghar baithe item rating part-time kaam! Bina interview roz Rs. 3,700 kamayi; Telegram join karke Rs. 950 kit deposit jama karein.",
            "Ellora Partner work-from-home naukri: Rozana Rs. 2,700 pakki income! Abhi Telegram par sampark karein aur Rs. 760 slot fee bhejein.",
            "Udupi Mart product tagging bharti! Daily payout Rs. 3,300 bank mein; shuru karne https://bit.ly/work-kit par Rs. 880 register karein.",
            "Social media promoter job vacancy! Roz INR 4,100 mobile se kamayein; Telegram trainer ko Rs. 900 registration fee bhejein.",
            "Udupi digital review work: Roz 2 ghante mein Rs. 2,950 pay; task ID chalu karwane Rs. 680 security fee turant send karo.",
            "Hotel portal review work: Guarantee Rs. 3,800 daily income; turant https://tinyurl.com/task-pass khol kar Rs. 1,080 kit charge bharo.",
        ]),
        ("hinglish", 1, "utility_disconnect_scam", "v8h_hi_utility_scam", None, [
            "Idukki Power cut warning: Pichle maah ka bill record mein update nahi hua, aaj raat 9:30 PM line kategi; turant 9811554433 par sampark karein.",
            "Teesta Water vibhag warning: Ghar ka paani connection aaj raat band hoga; bachne ke liye https://bit.ly/teesta-unblock par bill verify karo.",
            "Idukki prepaid meter alert! Supply chalu rakhne hetu abhi https://tinyurl.com/idukki-stay par ja kar Rs. 22 card se bhugtan karein.",
            "Spiti Telecom SIM barring chetavani: Aaj raat outgoing calls aur SIM lock hone wali hai, rokne 9700554433 par OTP batayein.",
            "Idukki Vidyut Kendra final notice: Ghar ki light aaj raat katne se rokne hetu remote support app chala kar 9822334411 par SMS code dein.",
            "Idukki meter update chetavani: Supply katne se pehle https://rb.gy/grid-stay khol kar consumer ID aur PIN bharo.",
        ]),

        # ==================== AMBIGUOUS HOLDOUT (24 = 12 EN + 12 HI, label=None) ====================
        ("english", None, "ambiguous_callback", "v8h_en_ambig_cb", None, [
            "Hi, calling from facilities desk regarding Friday fire-drill sheet; call back when at your seat.",
            "Please ring this internal extension regarding visitor four-wheeler pass collection.",
            "Hello, texting about solar inverter inspection requested yesterday; call back after 4:30 PM.",
            "Ping me on this number once you check the updated apartment parking circular.",
        ]),
        ("english", None, "ambiguous_payment_reminder", "v8h_en_ambig_pay", None, [
            "Reminder that Rs. 1,350 toward this month's staircase painting pool falls due Thursday.",
            "Hey, Rs. 390 shared airport cab fare from Monday night is still pending; settle whenever free.",
            "Squash court quarterly pass renewal INR 700 may be paid at sports desk before Tuesday.",
            "Workshop photocopy booklet share Rs. 410 per participant is payable ahead of Friday session.",
        ]),
        ("english", None, "ambiguous_sparse_link", "v8h_en_ambig_link", None, [
            "Uploaded revised society library timings and circular on https://block-board.example/library.",
            "Chess weekend rapid tournament pairings posted at https://chess-draw.example/saturday.",
            "Check updated conference room seating chart and agenda on https://hall-schedule.example/agenda.",
            "Quarterly water tank chlorination roster shared via https://estate-notice.example/tank.",
        ]),
        ("hinglish", None, "ambiguous_callback", "v8h_hi_ambig_cb", None, [
            "Bhaiya free ho kar is number par callback kar lena, shukrawar society meeting ke tent par baat karni thi.",
            "Hello, aapke car pollution certificate ke papers reception par rakhe hain; shaam ko phone kar lena.",
            "Zaroori baat karni thi, lab se nikal kar ek baar is mobile par ring karna.",
            "Gate number do par book parcel rakha hai, lene ke liye watchman ko call mila lo.",
        ]),
        ("hinglish", None, "ambiguous_payment_reminder", "v8h_hi_ambig_pay", None, [
            "Building garden maintenance hissa Rs. 550 is Guruwar tak office room mein jama karne ka reminder hai.",
            "Kal shaam ke snacks aur cold drink ke Rs. 320 baki hain, time milne par settle kar dena.",
            "Indoor badminton pass renew karne ke Rs. 500 agle Budhwar tak counter par de dein.",
            "Weekend trek tempo traveller advance Rs. 900 ka reminder—aaj raat tak list final karni hai.",
        ]),
        ("hinglish", None, "ambiguous_sparse_link", "v8h_hi_ambig_link", None, [
            "Cricket Sunday friendly match ka fixture https://ground-match.example/sunday par upload ho gaya hai.",
            "Society terrace waterproofing schedule https://wing-board.example/roof par dekh lein.",
            "Physics practical ke lab manuals aur notes https://lab-docs.example/manuals par mil jayenge.",
            "Hostel dining hall ka naya menu chart https://dining-chart.example/week par lag gaya hai.",
        ]),
    ]

    rows = []
    idx = 1
    for lang, label, category, family, pair_id, texts in specs:
        for text in texts:
            row = {
                "id": f"v8h{idx:03d}",
                "label": label,
                "language": lang,
                "category": category,
                "family": family,
                "source": "synthetic_v8_holdout",
                "text": text,
            }
            if pair_id is not None:
                row["pair_id"] = pair_id
            rows.append(row)
            idx += 1
    return rows


def main() -> None:
    v7_dev = read_jsonl(ROOT / "data/synthetic/v7_development.jsonl")
    v8_add = _build_v8_development_additions()
    v8_dev = v7_dev + v8_add
    v8_hold = build_v8_holdout()

    ids_dev = set()
    for r in v8_dev:
        assert r.get("split") in ("train", "calibration", "validation")
        assert r.get("label") in (0, 1)
        assert r["id"] not in ids_dev, f"Duplicate id {r['id']}"
        ids_dev.add(r["id"])
        r["text"] = normalize_sms(r["text"])
    check_leakage(v8_dev)

    ids_hold = set()
    for r in v8_hold:
        assert r.get("label") in (0, 1, None)
        assert r["id"] not in ids_hold, f"Duplicate holdout id {r['id']}"
        ids_hold.add(r["id"])
        r["text"] = normalize_sms(r["text"])

    assert sum(1 for r in v8_hold if r["label"] in (0, 1)) == 240
    assert sum(1 for r in v8_hold if r["label"] is None) == 24
    assert sum(1 for r in v8_hold if r["language"] == "english" and r["label"] == 0) == 60
    assert sum(1 for r in v8_hold if r["language"] == "english" and r["label"] == 1) == 60
    assert sum(1 for r in v8_hold if r["language"] == "hinglish" and r["label"] == 0) == 60
    assert sum(1 for r in v8_hold if r["language"] == "hinglish" and r["label"] == 1) == 60

    dev_fams_by_split = {
        sp: {r["family"] for r in v8_dev if r["split"] == sp}
        for sp in ("train", "calibration", "validation")
    }
    hold_fams = {r["family"] for r in v8_hold}
    for i, a in enumerate(("train", "calibration", "validation")):
        assert not (dev_fams_by_split[a] & hold_fams), f"Family overlap {a} vs holdout"
        for b in ("train", "calibration", "validation")[i + 1:]:
            assert not (dev_fams_by_split[a] & dev_fams_by_split[b]), f"Family overlap {a} vs {b}"

    external_rows = []
    for tag, rel in (
        ("v7_hold", "data/synthetic/v7_holdout.jsonl"),
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

    v8_hold_brands = (
        "pench", "hemavati", "sharavathi", "ellora", "udupi", "betwa",
        "idukki", "teesta", "dwaraka", "spiti", "netravati", "kasauli",
    )
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
        "harbor bank", "solstice", "meridian", "evergreen", "crestline",
        "banyan coop", "banyan", "oakwood", "cedar", "pinnacle", "sunrise mart", "horizon rail", "metro grid",
    )

    v8_add_blob = " \n ".join(r["text"].lower() for r in v8_add)
    for b in v8_hold_brands + v7_hold_brands + v6_hold_brands + v5_hold_brands + v4_hold_brands:
        assert b not in v8_add_blob, f"Leaked holdout entity {b!r} in V8 dev additions!"

    v8_hold_blob = " \n ".join(r["text"].lower() for r in v8_hold)
    for b in v7_hold_brands + v6_hold_brands + v5_hold_brands + v4_hold_brands + dev_brands:
        assert b not in v8_hold_blob, f"Leaked dev/prior-hold entity {b!r} in V8 holdout!"

    dev_canon = {canonical(r["text"]): r for r in v8_dev}
    hold_canon = {canonical(r["text"]): r for r in v8_hold}
    ext_canon = {canonical(r["text"]): r for r in external_rows}
    assert not (set(dev_canon) & set(hold_canon)), "Exact canonical overlap V8 dev vs V8 holdout!"
    assert not (set(dev_canon) & set(ext_canon)), f"Exact canonical overlap V8 dev vs ext: {set(dev_canon) & set(ext_canon)}"
    assert not (set(hold_canon) & set(ext_canon)), f"Exact canonical overlap V8 hold vs ext: {set(hold_canon) & set(ext_canon)}"

    tagged = (
        [{"id": r["id"], "partition": f"dev:{r['split']}", "text": r["text"]} for r in v8_dev]
        + [{"id": r["id"], "partition": "v8_hold", "text": r["text"]} for r in v8_hold]
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
        if len(parts_set) > 1 and any(item_id.startswith(("v8h", "v8d")) for item_id in ids):
            cross_hits.append(items)

    assert not cross_hits, f"V8 cross-partition near-duplicate collisions (>=0.85): {cross_hits}"

    dev_out = ROOT / "data/synthetic/v8_development.jsonl"
    hold_out = ROOT / "data/synthetic/v8_holdout.jsonl"
    write_jsonl(dev_out, v8_dev)
    write_jsonl(hold_out, v8_hold)

    summary = {
        "v8_development_sha256": digest(dev_out),
        "v8_holdout_sha256": digest(hold_out),
        "v8_dev_total": len(v8_dev),
        "v8_add_count": len(v8_add),
        "v8_dev_counts": {
            sp: {
                "total": sum(r["split"] == sp for r in v8_dev),
                "label_0": sum(r["split"] == sp and r["label"] == 0 for r in v8_dev),
                "label_1": sum(r["split"] == sp and r["label"] == 1 for r in v8_dev),
                "english": sum(r["split"] == sp and r["language"] == "english" for r in v8_dev),
                "hinglish": sum(r["split"] == sp and r["language"] == "hinglish" for r in v8_dev),
            }
            for sp in ("train", "calibration", "validation")
        },
        "v8_holdout_counts": {
            "total": len(v8_hold),
            "labeled": sum(r["label"] in (0, 1) for r in v8_hold),
            "ambiguous": sum(r["label"] is None for r in v8_hold),
            "english_0": sum(r["language"] == "english" and r["label"] == 0 for r in v8_hold),
            "english_1": sum(r["language"] == "english" and r["label"] == 1 for r in v8_hold),
            "hinglish_0": sum(r["language"] == "hinglish" and r["label"] == 0 for r in v8_hold),
            "hinglish_1": sum(r["language"] == "hinglish" and r["label"] == 1 for r in v8_hold),
        },
        "near_dup_cross_partition_085_v8_hits": len(cross_hits),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
