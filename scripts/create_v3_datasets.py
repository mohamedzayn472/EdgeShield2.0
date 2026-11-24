"""Generate strictly family-separated V3 development and held-out banking/scam datasets."""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
from edgeshield.datasets import canonical, check_leakage, group_near_duplicates, read_jsonl, write_jsonl
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]


def _make_dev_families() -> list[dict]:
    """Return diverse V3 banking & institutional development families across train/cal/val."""
    # Each entry: (family_id, split, language, label, category, texts)
    # Disjoint families per split ensure zero cross-split family or template leakage.
    specs = [
        # ======================== LEGITIMATE (label=0) — TRAIN ========================
        ("v3_en_credit_neft_tr", "train", "english", 0, "bank_credit", [
            "Your A/c XX4182 is credited with INR 14,500.00 on 12-Oct-26 via NEFT Ref NEFT2628501122. Avl Bal: INR 42,180.50.",
            "Dear Customer, Rs. 8,250.00 has been credited to your savings A/c XXXX7390 on 04/10/2026 by IMPS transfer. Clear balance is Rs. 19,640.00.",
            "Credit Alert: INR 32,000.00 deposited to A/c XX2091 on 01-Oct-26 towards monthly payroll. Available balance INR 67,410.75.",
            "Info: Rs 1,875.50 credited into your River Bank account XX6614 on 15-Oct-26 via RTGS. Ref UTR8821045912. Avl Bal Rs 28,900.25.",
            "A/c XX9045 credited by INR 640.00 on 18/10/2026 for quarterly savings interest. Updated balance: INR 11,220.40.",
            "Dear Account Holder, INR 4,300.00 refund credited to Card A/c XX3318 on 21-Oct-26 from Metro Rail booking.",
        ]),
        ("v3_en_debit_pos_tr", "train", "english", 0, "bank_debit", [
            "Rs. 1,420.00 debited from A/c XX5102 on 11-Oct-26 at City Pharmacy POS terminal. Avl Bal: Rs. 16,890.00. If not done by you call 18002586161.",
            "Alert: INR 3,500.00 withdrawn via ATM from your A/c XXXX8821 on 13/10/2026 at 18:42. Available balance: INR 21,105.00.",
            "Your A/c XX3947 is debited by INR 799.00 on 14-Oct-26 towards broadband auto-debit mandate. Ref MAND9901234. Call 18001023456 if unauthorized.",
            "Dear Customer, Rs. 625.50 has been debited from debit card XX7720 on 16-Oct-26 at Sunrise Supermarket. Avl Bal Rs. 9,412.30.",
            "Debit Alert: INR 2,150.00 deducted from A/c XX1823 on 19/10/2026 for electricity bill autopay. Balance remaining: INR 14,700.00.",
            "INR 5,000.00 debited from your savings A/c XX6409 via IMPS transfer on 22-Oct-26 Ref 629510448812. Report unauthorized txn on 18004251199.",
        ]),
        ("v3_en_statement_tr", "train", "english", 0, "bank_statement", [
            "Your monthly e-statement for Bank A/c XX4810 for September 2026 has been sent to your registered email ID.",
            "Dear Customer, your quarterly savings account statement for A/c XXXX2194 is ready to view inside your official mobile banking app.",
            "Credit Card XX9104 statement for cycle ending 15-Oct-26 is generated. Total due INR 6,420.00, minimum due INR 321.00, due date 04-Nov-26.",
            "Bank e-Statement alert: Statement for A/c XX3305 has been emailed to your registered address. Password format is your customer ID.",
            "Your annual interest certificate and account statement for FY 2025-26 can now be downloaded from netbanking.",
            "Dear Cardholder, your October statement for Apex Bank Card XX5541 has been dispatched to your registered email.",
        ]),
        ("v3_en_otp_txn_tr", "train", "english", 0, "banking_otp", [
            "739204 is your OTP for online transaction of INR 1,299.00 on River Bank Card XX4812 at BookStore. Valid for 10 mins. Do not share OTP with anyone.",
            "Dear Customer, use 518492 as your one-time password for netbanking login on 14-Oct-26. Valid for 5 minutes. Never share this OTP with anyone.",
            "OTP 864120 to add a new NEFT beneficiary in your savings A/c XX3019. Valid for 3 mins. Bank staff never ask for OTP.",
            "402917 is the verification code for Rs. 850.00 debit card purchase at City Mart. Do not disclose this OTP to any caller or message.",
            "Use OTP 295841 to authorize IMPS transfer of INR 4,500.00 from A/c XX6204. Expires in 10 mins. Never forward this code.",
            "Your Coastal Bank mobile banking login OTP is 641930. Valid for 5 mins. If you did not request this, ignore this SMS.",
        ]),
        ("v3_en_otp_short_tr", "train", "english", 0, "banking_otp", [
            "River Bank: Your OTP is 394812. Do not share it with anyone.",
            "Your one-time verification code is 718294. Keep this code confidential. Valid for 5 mins.",
            "Summit Bank login OTP: 502918. Never forward or disclose this SMS to any caller.",
            "OTP 841203 for internet banking sign-in. Valid for 5 mins. Ignore if not requested by you.",
            "Dear Customer, your 6-digit OTP is 263915 for mobile app access. Do not share with anyone.",
            "Coastal Bank: Enter OTP 619480 inside your official app only. Bank staff never ask for OTP.",
        ]),
        ("v3_en_upi_confirm_tr", "train", "english", 0, "upi_confirmation", [
            "Rs. 240.00 paid to Green Grocers via UPI from A/c XX4410 on 11-Oct-26. UPI Ref No 428510993412.",
            "UPI Alert: INR 1,100.00 debited from A/c XX7823 and credited to ananya@okaxis on 13-Oct-26. Ref 628910334455.",
            "You have received INR 650.00 from rohan@oksbi via UPI into A/c XX1904 on 15-Oct-26. UPI Ref 429103847561.",
            "Payment of Rs 95.00 to Metro Coffee House successful via UPI. A/c XX5502. Avl Bal Rs 8,320.00.",
            "UPI transaction of INR 3,200.00 to Rent Wallet completed on 17/10/2026. Reference number 529018273645.",
            "Dear Customer, your UPI AutoPay of INR 199.00 for Music Stream succeeded on 19-Oct-26 from A/c XX8120.",
        ]),
        ("v3_en_balance_tr", "train", "english", 0, "balance_notification", [
            "Available balance in your savings A/c XX4821 as of 12-Oct-26 09:00 is INR 27,450.80.",
            "Mini Statement for A/c XXXX9013: Clear Balance Rs. 15,890.25. Last txn: Cr Rs. 2,000.00 on 10-Oct-26.",
            "End-of-day balance summary: Your Summit Bank A/c XX2710 holds an available balance of INR 54,120.00 as on 14/10/2026.",
            "Balance Alert: Your current savings A/c XX6145 balance is Rs. 3,120.40 after recent transactions.",
            "Dear Customer, your monthly average balance in A/c XX3902 is currently Rs. 4,850.00. Maintain required balance to avoid quarterly charges.",
            "Avl Bal in A/c XX7315 on 18-Oct-26 is INR 19,205.60. Thank you for banking with us.",
        ]),
        ("v3_en_institution_tr", "train", "english", 0, "institutional_notice", [
            "Department Notice: Semester 5 lab examination schedule has been posted on the college notice board. Attendance is mandatory.",
            "Library Reminder: Your borrowed textbook Algorithms is due for return on 24-Oct-26. Renew at the campus library desk.",
            "Hostel Office: Mess menu feedback meeting is scheduled for Friday at 4:30 PM in the seminar hall.",
            "University Exam Cell: Hall tickets for November end-semester examinations can be collected from the department office tomorrow.",
            "Campus Placement Cell: Pre-placement talk for final-year ECE students starts at 10:00 AM in Auditorium B.",
            "Clinic Reminder: Your dental checkup appointment with Dr. Mehta is confirmed for Thursday at 11:15 AM.",
        ]),
        ("v3_hi_credit_debit_tr", "train", "hinglish", 0, "bank_credit_debit", [
            "Aapke A/c XX4120 mein INR 6,500.00 NEFT se jama hue hain. Avl Bal INR 23,400.00 hai.",
            "Soochna: Aapke Bank A/c XXXX5901 se Rs. 1,200.00 ATM se nikale gaye hain. Bacha hua balance Rs. 14,350.00 hai.",
            "Aapke savings account XX8312 mein Rs. 3,000.00 IMPS dwara credit hue hain on 12-Oct-26. Avl Bal Rs. 18,900.50.",
            "Aapke debit card XX2490 se INR 485.00 medical store par debit hue hain. Agar yeh aapne nahi kiya to 1800112233 par call karein.",
            "Aapke A/c XX7014 ka monthly e-statement aapke registered email par bhej diya gaya hai.",
            "Aapke Bank A/c XX3650 ka available balance 15-Oct-26 ko INR 12,780.00 hai.",
        ]),
        ("v3_hi_otp_upi_tr", "train", "hinglish", 0, "banking_otp_upi", [
            "582914 aapka netbanking login OTP hai. Yeh 5 minute tak valid hai. Kripya OTP kisi ke saath share na karein.",
            "Aapke card XX6190 ke Rs. 750.00 transaction ke liye OTP 319402 hai. Kisi ko bhi OTP mat batayein.",
            "UPI se Rs. 320.00 Sharma Kirana ko safaltapoorvak bheje gaye. UPI Ref 428719023451. A/c XX9011.",
            "Aapko UPI dwara Priya se INR 1,500.00 prapt hue hain. A/c XX4482 mein jama ho gaye hain.",
            "Aapke Bank A/c XX1298 ka October statement mobile app mein uplabdh hai.",
            "College notice: Kal subah 9 baje AI lab ki extra class room 204 mein hogi.",
        ]),
        ("v3_hi_otp_extended_tr", "train", "hinglish", 0, "banking_otp", [
            "Naye payee ko jodne ke liye aapka 6-digit OTP 481920 hai. Bank staff kabhi bhi OTP nahi maangta.",
            "Online shopping INR 1,249.00 ke payment ke liye OTP 703518 daalein. Yeh verification code kisi ko forward mat karein.",
            "Aapke mobile banking app sign-in ka verification code 918273 hai. 5 mins tak valid hai, kisi ko mat batana.",
            "UPI app activation ke liye OTP 364829 manga gaya hai. Agar yeh request aapki nahi hai to SMS ignore kar dein.",
            "Aapke debit card XX4419 ke Rs. 620.00 bill payment ka OTP 852041 hai. Kripya code gupt rakhein.",
            "IMPS transfer shuru karne ke liye OTP 195734 use karein. Bank karamchari phone par OTP nahi poochte.",
        ]),
        ("v3_benign_info_links_tr", "train", "english", 0, "institutional_notice", [
            "Department update: The seminar timetable for next week is published at https://campus-dept.example/timetable with no sign-in needed.",
            "Community library newsletter: Saturday reading list is posted at https://city-library.example/books for all subscribers.",
            "Sports club notice: Weekend practice schedule is available at https://sports-club.example/schedule for members.",
            "College music society ki rehearsal timing https://music-society.example/events par aa gayi hai, dekhne ke liye login zaroori nahi.",
            "Robotics workshop ka venue update https://tech-club.example/workshop par public hai, students wahan check kar sakte hain.",
            "City museum ki weekend exhibition guide https://museum-guide.example/exhibits par free mein padh sakte hain.",
        ]),

        # ======================== SCAM (label=1) — TRAIN ========================
        ("v3_en_scam_block_tr", "train", "english", 1, "scam_account_block", [
            "URGENT: Your bank account XX4821 will be blocked today at 6 PM. Update KYC immediately at https://kyc-update-bank.example to avoid suspension.",
            "Dear Customer, your netbanking access has been suspended due to incomplete verification. Reactivate now at https://bit.ly/bank-unlock-now.",
            "Final Warning: Your debit card and savings account will be frozen within 2 hours. Verify your account immediately at http://verify-acct-alert.example.",
            "Alert from Bank Security: Unusual login detected, your A/c is on hold. Call immediately on 9876501234 and verify details to unblock.",
            "Your SBI-style netbanking account will be deactivated tonight. Click https://tinyurl.com/reactivate-ac to keep your account active.",
            "Account Restriction Notice: Your bank A/c has been temporarily locked. Submit PAN and KYC at https://bank-portal-verify.example right now.",
        ]),
        ("v3_en_scam_otp_pin_tr", "train", "english", 1, "scam_otp_pin", [
            "Dear Customer, an unauthorized debit of INR 9,500.00 was attempted on your account. Share your 6-digit OTP immediately to cancel and refund.",
            "Bank Support Alert: To stop your card from being blocked, reply with the OTP sent to your mobile right now.",
            "Your bank refund of Rs. 4,200.00 is pending. Send your OTP and UPI PIN to our executive to release the amount into your account.",
            "Urgent verification from Card Dept: Please provide your 4-digit ATM PIN and the verification code you received to reactivate your debit card.",
            "Bank fraud desk: Tell us the one-time password immediately so we can reverse the suspicious transfer on A/c XX5512.",
            "To complete your reward points redemption of Rs. 3,500 on your bank card, share your OTP and MPIN now.",
        ]),
        ("v3_en_scam_short_otp_tr", "train", "english", 1, "scam_otp_pin", [
            "Urgent: Reply with your 6-digit OTP now to cancel the pending transfer on your bank account.",
            "Bank Support: Send us the OTP you just received so we can release your refund.",
            "Share your verification code immediately or your debit card will be blocked today.",
            "Please forward the login OTP sent to your phone to our agent to verify your account.",
            "Send your OTP and ATM PIN right now to stop unauthorized activity on your card.",
            "Reply with the code from your bank SMS immediately to complete KYC verification.",
        ]),
        ("v3_en_scam_kyc_tr", "train", "english", 1, "scam_fake_kyc", [
            "Dear Customer, your bank KYC has expired today. Update KYC immediately via https://kyc-bank-renewal.example or your account will be frozen.",
            "PAN card not linked with your bank A/c. Complete instant e-KYC at https://bit.ly/pan-kyc-fix within 24 hours to avoid account closure.",
            "Urgent Bank Notice: Aadhaar and KYC verification is overdue. Click https://update-kyc-online.example and submit your details right now.",
            "Your mobile banking KYC is pending. Account outgoing transfers will be suspended today unless you verify at https://ekyc-helpdesk.example.",
            "Reminder: Bank KYC update mandatory before midnight. Open https://tinyurl.com/bank-ekyc-verify and enter account details immediately.",
            "Dear Account Holder, your KYC failed re-verification. Update your identity verification at https://bank-kyc-desk.example to prevent deactivation.",
        ]),
        ("v3_en_scam_bank_link_tr", "train", "english", 1, "scam_bank_link", [
            "Your bank reward points worth INR 6,800 expire tonight. Claim cash credit immediately at https://bit.ly/bank-points-claim.",
            "Bank Tax Refund: INR 11,400.00 approved for your A/c. Visit https://refund-bank-credit.example and log in to receive credit.",
            "Alert: Your credit card limit has been pre-approved for Rs. 2,50,000. Click https://card-limit-upgrade.example to activate now.",
            "Important Bank Message: Download the updated security certificate from https://tinyurl.com/bank-apk-sec to continue netbanking.",
            "Dear Customer, view your locked bank statement and unblock funds at https://secure-statement-login.example immediately.",
            "Your UPI handle on Bank A/c is restricted. Open https://upi-bank-unblock.example right now and confirm your account.",
        ]),
        ("v3_en_scam_cred_tr", "train", "english", 1, "scam_credentials", [
            "Urgent Bank Alert: Enter your debit card number, expiry date, and CVV at https://verify-card-secure.example to unlock your card.",
            "Dear Customer, verify your netbanking login ID and password immediately at https://netbank-confirm.example or access will be deactivated.",
            "Bank Helpdesk: Provide your CVV, ATM PIN, and date of birth to confirm your identity and reverse the Rs. 7,000 hold.",
            "Your bank account security upgrade requires your MPIN and card details. Submit credentials right now at https://bank-sec-update.example.",
            "Urgent: Confirm your banking password and login details by replying to this message so we can lift the freeze on your account.",
            "Card Verification Required: Send your 16-digit card number and CVV immediately to avoid permanent block on your bank card.",
        ]),
        ("v3_hi_scam_bank_tr", "train", "hinglish", 1, "scam_hinglish_bank", [
            "Turant dhyan dein: Aapka bank account aaj block ho jayega. KYC update karne ke liye abhi https://bit.ly/kyc-turant kholein.",
            "Priya grahak, aapka ATM card suspend hone wala hai. Unblock karne ke liye apna OTP aur ATM PIN turant bhejein.",
            "Aapke bank A/c ka PAN KYC pending hai. Aaj raat se pehle https://bank-kyc-seva.example par login password daalein nahi to khata band hoga.",
            "Bank security alert: Aapke account se galat payment rokne ke liye aaya hua OTP abhi batao.",
            "Jaldi karo: Aapke bank reward Rs. 5,000 aaj expire honge, claim karne ke liye https://tinyurl.com/bank-inaam par card number aur CVV enter karo.",
            "Aapka netbanking freeze kar diya gaya hai. Chalu rakhne ke liye apna UPI PIN aur OTP turant share karo.",
        ]),
        ("v3_en_scam_sim_support_tr", "train", "english", 1, "scam_otp_pin", [
            "Telecom KYC Notice: Your mobile SIM will be disconnected tonight. Forward the verification code from your payment app to our support desk now.",
            "SIM upgrade mandatory: Send the incoming bank authentication code to this number so we can keep your cellular service active.",
            "Customer Care Alert: Reply with your login passcode and recovery code immediately to cancel the unauthorized SIM port request.",
            "Urgent Helpline: Install remote support software on your phone and share your incoming OTP so our technician can fix your wallet.",
            "Account Safety Desk: Do not call the branch; send your backup login codes directly to this officer to stop profile deletion.",
            "Payment Recovery Support: Forward the 6-digit code arriving on your phone to reverse the duplicate debit.",
        ]),
        ("v3_en_scam_voucher_deposit_tr", "train", "english", 1, "scam_credentials", [
            "Utility Disconnection Alert: Your power meter will be cut tonight. Pay overdue dues by buying digital gift vouchers and replying with the voucher codes.",
            "Director Urgent Request: Purchase prepaid gift cards for an urgent client payment and text me the redemption codes immediately.",
            "Online Task Earnings: Your INR 18,000 bonus is locked. Transfer an INR 2,500 unlock deposit to the agent wallet; fee cannot be deducted from earnings.",
            "Marketplace Buyer Notice: I have sent a payment collect request to your UPI app. Approve the debit and enter your UPI PIN to receive the amount.",
            "Lucky Draw Department: You won a cash award without registering. Send INR 1,100 processing tax first to release your prize money.",
            "Remote Hiring Desk: Selected without interview. Pay a refundable registration deposit of INR 1,999 today to confirm your work-from-home offer.",
        ]),
        ("v3_hi_scam_sim_remote_tr", "train", "hinglish", 1, "scam_hinglish_bank", [
            "Telecom update: Aapka SIM aaj raat band hoga, network chalu rakhne ke liye payment app ka login code aur OTP reply karo.",
            "Helpline executive bol raha hoon: Phone par screen sharing app chalu karo aur OTP mat chhupana, main refund khud approve karunga.",
            "Aapke bank account par temporary hold laga hai. Hold hatane ke liye jo OTP abhi aaye woh yahin SMS mein bhej do.",
            "Electricity department warning: Aaj bijli kat jayegi, bill clear karne ke liye digital gift card code turant reply mein bhejo.",
            "Sarkari sahayata rashi manzoor hui hai, paisa lene se pehle agent ko refundable security deposit transfer karo.",
            "Investment wallet se profit nikalne ke liye pehle alag unlock fee bhejni hogi, munafe se fee nahi kat sakti.",
        ]),
        ("v3_en_scam_impersonation_no_url_tr", "train", "english", 1, "scam_account_block", [
            "Urgent Bank Notice: Your savings A/c is flagged for immediate closure. Reply with your PAN, debit card number, and OTP to keep it open.",
            "Bank Compliance Officer: Your account outgoing transfers are on hold. Send your MPIN and card expiry date immediately to lift the hold.",
            "Credit Card Fraud Desk: An international swipe of INR 24,500 is queued. Tell us the 6-digit OTP right now to block the charge.",
            "Netbanking Admin: Password reset mandatory today. Reply with your current login ID and password so we can manually renew access.",
            "Debit Card Department: Your card has been suspended for incomplete KYC. Share your ATM PIN and CVV immediately to reactivate.",
            "Bank Refund Officer: Your failed IMPS of INR 6,400 is ready for reversal. Confirm your UPI PIN and OTP now to credit your account.",
        ]),
        ("v3_hi_scam_no_url_tr", "train", "hinglish", 1, "scam_hinglish_bank", [
            "Bank adhikari bol raha hoon: Aapke khate par rok lagne wali hai, turant apna password aur login OTP reply mein bhejein.",
            "Aapka refund taiyar hai, payment app mein aayi pay request approve karke apna UPI PIN daalo tab paise credit honge.",
            "Aapne entry nahi ki par lucky draw mein Rs. 50,000 jeete hain, inaam paane ke liye pehle tax amount agent ko transfer karo.",
            "Credit card limit badhane ke liye apna 16-digit card number, expiry aur CVV abhi SMS par bhej dein.",
            "Aapke email aur banking profile delete hone wale hain, manual renewal ke liye apna password aur recovery code turant batao.",
            "Kisi ko call mat karo, apna ATM PIN aur aaya hua verification code seedha mujhe reply karo taaki card unblock ho sake.",
        ]),

        # ======================== CALIBRATION SPLIT (disjoint families) ========================
        ("v3_en_legit_bank_cal", "calibration", "english", 0, "bank_credit_debit", [
            "INR 12,400.00 credited to your A/c XX8841 on 03-Nov-26 via NEFT salary settlement. Avl Bal: INR 38,910.00.",
            "Rs. 540.00 debited from A/c XX2109 on 04-Nov-26 at Metro Fuel Station POS. Available balance Rs. 11,450.20. Call 1800223344 if unauthorized.",
            "Your e-statement for Bank A/c XX5732 for October 2026 has been sent to your registered email address.",
            "619284 is your OTP for Rs. 1,499.00 purchase on Summit Bank Card XX9401. Valid for 10 mins. Do not share OTP with anyone.",
            "Rs. 180.00 paid to Campus Cafe via UPI from A/c XX3190 on 05-Nov-26. UPI Ref No 430918274651.",
            "Closing balance update: Your savings account XX6028 holds INR 22,615.45 clear funds as on 06-Nov-26.",
        ]),
        ("v3_hi_legit_bank_cal", "calibration", "hinglish", 0, "bank_mixed", [
            "Aapke A/c XX7142 mein INR 4,800.00 IMPS se credit hue hain. Avl Bal INR 16,200.00 hai.",
            "Aapke Bank A/c XX3380 se Rs. 650.00 UPI payment ke liye debit hue hain. UPI Ref 531092837465.",
            "804129 aapka bank login OTP hai. Yeh 5 minute ke liye valid hai. Kisi ke saath share mat karo.",
            "Aapka October mahine ka bank statement registered email ID par bhej diya gaya hai.",
            "Aapke savings account XX9215 mein 06-Nov-26 ko available balance Rs. 9,840.50 hai.",
            "College soochana: Kal 11 baje seminar hall mein project review meeting hai.",
        ]),
        ("v3_en_scam_bank_cal", "calibration", "english", 1, "scam_bank_mixed", [
            "URGENT: Your bank account XX5012 will be suspended today. Update KYC now at https://verify-kyc-bank.example to avoid block.",
            "Dear Customer, share your 6-digit OTP immediately to stop an unauthorized Rs. 8,500 debit from your bank A/c.",
            "Your debit card is temporarily locked. Enter card number, CVV, and ATM PIN at https://bit.ly/unlock-card-fast.",
            "PAN verification overdue on your bank A/c. Complete KYC right now at https://pan-bank-portal.example or account will be closed.",
            "Bank Support: Please reply with your netbanking password and verification code to reactivate your frozen account.",
            "Claim INR 4,900 bank cashback before midnight by logging in at https://tinyurl.com/cashback-bank-now.",
        ]),
        ("v3_hi_scam_bank_cal", "calibration", "hinglish", 1, "scam_hinglish_bank", [
            "Urgent: Aapka bank khata aaj freeze ho jayega. Abhi https://bit.ly/khata-kyc par KYC update karo.",
            "Bank officer bol raha hoon, aapka card block hone se bachane ke liye OTP aur PIN turant bhejo.",
            "Aapke account mein Rs. 6,000 refund atka hai, paise lene ke liye apna UPI PIN aur OTP share karein.",
            "Aapka netbanking band ho raha hai. Turant https://netbank-chalu.example par password aur CVV daalo.",
            "Jaldi karo: Aapka bank PAN link nahi hai, aaj raat tak https://pan-update-now.example par verify karo.",
            "Aapka debit card deactivate kar diya gaya hai, reactivate karne ke liye card number aur OTP batao.",
        ]),

        # ======================== VALIDATION SPLIT (disjoint families) ========================
        ("v3_en_legit_credit_val", "validation", "english", 0, "bank_credit", [
            "Dear Customer, INR 9,750.00 has been credited to your A/c XX4092 on 08-Nov-26 via NEFT transfer. Avl Bal: INR 31,420.00.",
            "Credit Alert: Rs. 3,200.00 deposited into A/c XXXX6815 on 09/11/2026 via IMPS Ref 631390881234. Available balance Rs. 17,650.50.",
            "Your savings A/c XX2519 has been credited with INR 1,125.00 towards merchant cashback reversal on 10-Nov-26.",
            "Info: Rs. 25,000.00 salary credit posted to Bank A/c XX8304 on 01-Nov-26. Clear balance is Rs. 48,920.75.",
            "INR 410.00 quarterly interest credited to your River Bank A/c XX1476 on 11-Nov-26. Avl Bal INR 14,110.20.",
            "Rs. 2,850.00 refund credited to your Bank Card XX5930 from Rail Booking on 12-Nov-26.",
        ]),
        ("v3_en_legit_debit_stmt_val", "validation", "english", 0, "bank_debit_stmt", [
            "Rs. 2,100.00 debited from A/c XX6318 on 09-Nov-26 at ATM withdrawal. Avl Bal: Rs. 19,430.00. If not done by you call 18002586161.",
            "Alert: Your A/c XX9142 is debited by INR 949.00 on 10-Nov-26 towards UPI/Merchant payment. Call customer care if unauthorized.",
            "INR 4,250.00 auto-debited from savings A/c XX3801 on 11-Nov-26 for mutual fund SIP mandate. Avl Bal INR 26,800.00.",
            "Your monthly e-statement for Bank A/c XX7420 for October 2026 has been emailed to your registered email ID.",
            "Dear Cardholder, your credit card XX4611 statement has been generated. Total due Rs. 4,890.00 payable by 28-Nov-26.",
            "Available balance in your Bank A/c XX5289 as on 12-Nov-26 is INR 33,190.40.",
        ]),
        ("v3_en_legit_otp_upi_val", "validation", "english", 0, "banking_otp_upi", [
            "491820 is your OTP for transaction of INR 799.00 on your Apex Bank Card XX3412. Valid for 10 mins. Do not share OTP with anyone.",
            "Your OTP for netbanking login is 837105. Valid for 5 minutes. Never share this code with anyone.",
            "Dear Customer, use OTP 204916 to authorize your UPI registration on A/c XX8014. Do not disclose this OTP to anyone.",
            "Rs. 450.00 paid to Fresh Foods via UPI from A/c XX6621 on 10-Nov-26. UPI Ref No 431409812345.",
            "UPI Credit: INR 1,800.00 received from vikram@okicici into A/c XX2904 on 11-Nov-26. Ref 531590128374.",
            "Notice: Mid-semester timetable for Computer Science has been updated on the college portal. Regular labs continue Tuesday.",
        ]),
        ("v3_hi_legit_bank_val", "validation", "hinglish", 0, "bank_mixed", [
            "NEFT credit alert: INR 7,200.00 aapke savings khate XX5410 mein deposit hue hain, naya balance INR 29,100.00 hai.",
            "Aapke Bank A/c XX8194 se Rs. 950.00 POS card swipe se debit hue hain. Balance Rs. 11,230.50 hai.",
            "912408 aapke online card payment ka OTP hai. 10 minute tak valid hai. Kripya OTP kisi ko mat batayein.",
            "UPI se Rs. 275.00 Verma Medical ko payment safal hua. UPI Ref 431609281736.",
            "Aapke savings A/c XX2067 ka e-statement registered email par bhej diya gaya hai.",
            "Aapke Bank A/c XX6741 ka available balance 12-Nov-26 ko Rs. 15,640.00 hai.",
        ]),
        ("v3_en_scam_block_kyc_val", "validation", "english", 1, "scam_block_kyc", [
            "Urgent: Your bank account XX8012 will be blocked within 2 hours. Complete KYC immediately at https://bit.ly/kyc-bank-urgent.",
            "Dear Customer, your savings A/c is suspended due to expired PAN KYC. Verify right now at https://ekyc-bank-update.example.",
            "Final Notice: Your debit card will be deactivated today unless you update KYC at https://tinyurl.com/card-kyc-fix.",
            "Alert: Bank account on hold due to suspicious activity. Click https://unblock-my-bank.example and log in immediately.",
            "Your mobile banking access will be frozen tonight. Submit identity verification at https://bank-verify-portal.example now.",
            "Account Closure Warning: Update your Aadhaar and bank KYC immediately at https://kyc-reverify-bank.example.",
        ]),
        ("v3_en_scam_otp_cred_val", "validation", "english", 1, "scam_otp_cred", [
            "Bank Fraud Alert: Rs. 12,000 debit pending on your A/c. Share the 6-digit OTP immediately to cancel the transaction.",
            "Dear User, reply with your OTP and ATM PIN right now to reactivate your blocked bank debit card.",
            "Urgent Card Security: Enter your 16-digit card number, expiry, and CVV at https://card-unlock-desk.example immediately.",
            "Your bank refund of INR 3,800 is ready. Provide your netbanking login ID and password at https://refund-bank-login.example.",
            "Support Desk: Send your UPI PIN and verification code immediately to reverse the failed transfer on A/c XX4190.",
            "Confirm your banking MPIN and CVV now to lift the temporary freeze on your credit card.",
        ]),
        ("v3_hi_scam_bank_val", "validation", "hinglish", 1, "scam_hinglish_bank", [
            "Jaldi karein: Aapka bank account aaj band ho jayega. KYC verify karne ke liye https://bit.ly/bank-kyc-abhi kholein.",
            "Bank helpline se soochna: Aapke account se galat debit rokne ke liye aaya hua OTP turant share karo.",
            "Aapka ATM card block ho gaya hai. Unblock karne ke liye card number, CVV aur PIN abhi bhejein.",
            "Aapka PAN KYC expire ho gaya hai. Turant https://kyc-bank-portal.example par netbanking password enter karo.",
            "Bank reward Rs. 4,500 claim karne ke liye https://tinyurl.com/bank-reward-now par apna UPI PIN aur OTP daalein.",
            "Aapke khate par rok lag gayi hai, turant reactivate karne ke liye apna MPIN aur OTP batao.",
        ]),
    ]

    rows = []
    for fam, split, lang, label, cat, texts in specs:
        for i, txt in enumerate(texts, 1):
            rows.append({
                "id": f"{fam}_{i:02d}",
                "text": normalize_sms(txt),
                "label": label,
                "language": lang,
                "family": fam,
                "split": split,
                "category": cat,
                "source": "synthetic_v3_banking_expansion",
            })
    return rows


def _make_holdout_dataset() -> list[dict]:
    """Strictly separate 160-message V3 held-out test set (80 legit + 80 scam, En + Hinglish)."""
    # Distinct bank names (Orion, Harbor, Valley, Crest, Beacon, Meridian, Lotus, Banyan, Deccan, Indus-style)
    # and distinct phrasing from v3_development.jsonl.
    items = [
        # ---------- LEGITIMATE ENGLISH (40) ----------
        # 1. Bank credit notifications (7)
        ("english", 0, "bank_credit", "Orion Bank: INR 18,500.00 has been credited to your A/c XX7301 on 19-Nov-26 by NEFT from TechCorp Payroll. Avl Bal INR 52,340.00."),
        ("english", 0, "bank_credit", "Dear Patron, Rs. 4,120.50 received into savings A/c XXXX2948 via IMPS on 18/11/2026. Updated balance is Rs. 21,875.50."),
        ("english", 0, "bank_credit", "Credit confirmation: INR 750.00 cashback posted to Harbor Bank A/c XX5190 on 17-Nov-26. Ref CR88291034."),
        ("english", 0, "bank_credit", "RTGS transfer of INR 65,000.00 credited to your A/c XX9402 on 16-Nov-26. Clear balance stands at INR 1,12,400.00."),
        ("english", 0, "bank_credit", "Rs. 920.00 dividend payout has been deposited into your Bank A/c XX3811 on 15-Nov-26. Avl Bal Rs. 14,560.80."),
        ("english", 0, "bank_credit", "Refund processed: INR 1,649.00 credited back to Valley Bank Card XX6024 from Airline Desk on 19-Nov-26."),
        ("english", 0, "bank_credit", "A/c XX1185 credited by INR 3,300.00 on 20-Nov-26 via IMPS from Rajesh Kumar. Avl Bal: INR 19,210.00."),

        # 2. Bank debit notifications (7)
        ("english", 0, "bank_debit", "Rs. 2,400.00 debited from A/c XX8412 on 19-Nov-26 towards ATM cash withdrawal at MG Road. Avl Bal Rs. 18,920.00. Call 18001080 if not done by you."),
        ("english", 0, "bank_debit", "Debit Alert: INR 1,180.00 spent on Crest Bank Debit Card XX5027 at Book Depot on 18-Nov-26. Available balance: INR 13,440.50."),
        ("english", 0, "bank_debit", "Your A/c XXXX3904 was debited by INR 6,200.00 on 17/11/2026 for scheduled home EMI auto-debit. Remaining balance INR 34,110.00."),
        ("english", 0, "bank_debit", "INR 349.00 deducted from savings A/c XX7715 on 16-Nov-26 for fiber internet bill payment. Ref BILL9021847."),
        ("english", 0, "bank_debit", "Dear Customer, Rs. 4,750.00 debited from A/c XX2608 via NEFT transfer on 19-Nov-26. Report unauthorized activity on toll-free 18002026161."),
        ("english", 0, "bank_debit", "POS purchase of INR 890.00 debited from card XX9153 at Organic Mart on 20-Nov-26. Avl Bal INR 7,610.25."),
        ("english", 0, "bank_debit", "Auto-debit of INR 1,500.00 executed on A/c XX4489 on 15-Nov-26 towards recurring deposit installment."),

        # 3. Bank statements (6)
        ("english", 0, "bank_statement", "Your e-statement for Orion Bank A/c XX7301 for October 2026 has been delivered to your registered email ID."),
        ("english", 0, "bank_statement", "Dear Cardholder, your monthly statement for Beacon Credit Card XX8124 is ready. Total due INR 8,240.00 by 05-Dec-26."),
        ("english", 0, "bank_statement", "Quarterly savings account statement for A/c XXXX5509 is now available under Documents inside your official banking app."),
        ("english", 0, "bank_statement", "Your October 2026 PDF statement for Meridian Bank A/c XX2390 has been emailed. Open with your registered DOB password."),
        ("english", 0, "bank_statement", "Annual TDS and deposit statement for A/c XX6140 can be downloaded anytime via official internet banking."),
        ("english", 0, "bank_statement", "Statement Notification: Credit card XX3048 billing summary for November has been sent to your registered email."),

        # 4. Banking OTP messages (7)
        ("english", 0, "banking_otp", "849201 is your OTP for online purchase of INR 2,199.00 on Harbor Bank Card XX5190 at Electronics Hub. Valid for 10 mins. Do not share OTP with anyone."),
        ("english", 0, "banking_otp", "Use one-time password 371940 to sign in to Valley Bank netbanking. Expires in 5 minutes. Never disclose this OTP to anyone."),
        ("english", 0, "banking_otp", "OTP 604827 requested for adding a new IMPS payee on A/c XX9402. Valid for 3 mins. Bank employees never ask for your OTP."),
        ("english", 0, "banking_otp", "529183 is the verification code for Rs. 640.00 card transaction at Metro Pharmacy. Do not share this code with any person."),
        ("english", 0, "banking_otp", "Dear Customer, enter OTP 194738 inside your own mobile app to confirm biller registration. Valid for 5 mins. Never forward this SMS."),
        ("english", 0, "banking_otp", "710492 is your 6-digit OTP for UPI PIN reset requested by you on A/c XX3811. If not initiated by you, ignore this message."),
        ("english", 0, "banking_otp", "Your Crest Bank internet banking login OTP is 462815, valid for 5 mins. Keep this code confidential."),

        # 5. UPI payment confirmations (5)
        ("english", 0, "upi_confirmation", "Rs. 165.00 paid to Corner Bakery via UPI from A/c XX7301 on 19-Nov-26. UPI Ref No 432419082736."),
        ("english", 0, "upi_confirmation", "UPI Debit: INR 1,450.00 transferred to deepak@okhdfcbank from A/c XX5027 on 18-Nov-26. Ref 632309182745."),
        ("english", 0, "upi_confirmation", "You received INR 900.00 from meera@okaxis via UPI into A/c XX2608 on 19-Nov-26. UPI Ref 532491827364."),
        ("english", 0, "upi_confirmation", "UPI payment of Rs. 520.00 to City Cabs completed successfully. A/c XX9153. Avl Bal Rs. 6,840.00."),
        ("english", 0, "upi_confirmation", "Mandate executed: INR 299.00 paid via UPI AutoPay for Cloud Storage from A/c XX4489 on 17-Nov-26."),

        # 6. Balance notifications (4)
        ("english", 0, "balance_notification", "Balance Enquiry: Your Orion savings account XX7301 carries clear funds of INR 49,940.00 at 08:30 on 20-Nov-26."),
        ("english", 0, "balance_notification", "Mini Statement for A/c XXXX8412: Clear Balance Rs. 18,920.00. Last debit Rs. 2,400.00 on 19-Nov-26."),
        ("english", 0, "balance_notification", "Beacon Bank Balance Alert: Your A/c XX6140 holds an available balance of INR 31,205.75 as on 19/11/2026."),
        ("english", 0, "balance_notification", "Informational reminder: Current balance in savings A/c XX2390 is Rs. 2,450.00. Please check your app for monthly balance norms."),

        # 7. Institutional / college announcements (4)
        ("english", 0, "institutional_notice", "Academic Circular: Final-year project presentation slots for Friday have been emailed to all student teams."),
        ("english", 0, "institutional_notice", "College Admin: Tuition fee receipt for Autumn 2026 is ready for pickup at the accounts counter."),
        ("english", 0, "institutional_notice", "Sports Committee: Inter-department badminton trials begin tomorrow at 5:00 PM in the indoor court."),
        ("english", 0, "institutional_notice", "Train Update: PNR 4829103847 Coach B3 Seat 24 is confirmed for departure at 21:15 from Central Station."),

        # ---------- LEGITIMATE HINGLISH (40) ----------
        # 1. Bank credit (7)
        ("hinglish", 0, "bank_credit", "Aapke A/c XX8201 mein INR 11,000.00 NEFT se credit hue hain on 19-Nov-26. Avl Bal INR 36,450.00 hai."),
        ("hinglish", 0, "bank_credit", "Lotus Bank soochna: Aapke khate XX4912 mein Rs. 3,450.00 IMPS dwara jama ho gaye hain. Bacha balance Rs. 17,900.50 hai."),
        ("hinglish", 0, "bank_credit", "Aapke savings account XX6305 mein Rs. 580.00 quarterly interest jama hua hai. Updated balance Rs. 12,340.00."),
        ("hinglish", 0, "bank_credit", "Salary credit: INR 28,500.00 aapke Banyan Bank A/c XX2094 mein jama kiye gaye hain on 01-Nov-26."),
        ("hinglish", 0, "bank_credit", "Aapke card XX7741 par INR 1,299.00 ka refund wapas aa gaya hai. Yeh sirf transaction soochna hai."),
        ("hinglish", 0, "bank_credit", "RTGS dwara INR 40,000.00 aapke A/c XX5108 mein prapt hue hain. Avl Bal INR 78,210.00 hai."),
        ("hinglish", 0, "bank_credit", "Aapke A/c XXXX9032 mein Rs. 2,100.00 cashback aur refund jama ho gaya hai on 18-Nov-26."),

        # 2. Bank debit (7)
        ("hinglish", 0, "bank_debit", "Aapke A/c XX8201 se Rs. 1,800.00 ATM se nikale gaye hain on 19-Nov-26. Avl Bal Rs. 34,650.00 hai. Agar aapne nahi kiya to 1800123456 par call karein."),
        ("hinglish", 0, "bank_debit", "Debit alert: Aapke Deccan Bank card XX3194 se INR 645.00 medical store par kharch hue hain. Balance INR 9,820.00 hai."),
        ("hinglish", 0, "bank_debit", "Aapke savings A/c XX5520 se INR 3,100.00 bijli bill autopay ke liye kate hain on 17-Nov-26."),
        ("hinglish", 0, "bank_debit", "Rs. 920.00 aapke A/c XX6740 se POS shopping ke liye debit kiye gaye hain. Bacha balance Rs. 15,110.25."),
        ("hinglish", 0, "bank_debit", "Aapke khate XX2918 se INR 2,500.00 SIP mandate ke liye auto-debit hue hain on 15-Nov-26."),
        ("hinglish", 0, "bank_debit", "IMPS transfer ke liye aapke A/c XX4105 se Rs. 5,000.00 debit hue hain. Ref 632410982341."),
        ("hinglish", 0, "bank_debit", "Aapke debit card XX9811 se INR 310.00 petrol pump par payment hua hai. Avl Bal INR 8,490.00."),

        # 3. Bank statement (6)
        ("hinglish", 0, "bank_statement", "Aapke Lotus Bank A/c XX4912 ka October 2026 ka e-statement aapke registered email ID par bhej diya gaya hai."),
        ("hinglish", 0, "bank_statement", "Aapke credit card XX7741 ka monthly statement ban gaya hai. Total bill Rs. 5,420.00 hai, due date 02-Dec-26."),
        ("hinglish", 0, "bank_statement", "Aapke savings account XX6305 ka quarterly statement official mobile banking app mein dekh sakte hain."),
        ("hinglish", 0, "bank_statement", "Soochna: Banyan Bank A/c XX2094 ka PDF statement aapke registered email par bheja gaya hai."),
        ("hinglish", 0, "bank_statement", "Aapke khate XX5108 ka varshik interest certificate netbanking portal par download ke liye uplabdh hai."),
        ("hinglish", 0, "bank_statement", "Card statement alert: November ka bill summary aapke registered email par aa gaya hai."),

        # 4. Banking OTP (7)
        ("hinglish", 0, "banking_otp", "472910 aapke Lotus Bank card XX4912 ke Rs. 1,150.00 transaction ka OTP hai. 10 minute tak valid hai. Kisi ke saath share mat karein."),
        ("hinglish", 0, "banking_otp", "Aapka netbanking login OTP 930184 hai. Yeh 5 minute mein expire hoga. Kripya OTP kisi ko na batayein."),
        ("hinglish", 0, "banking_otp", "Naya beneficiary jodne ke liye aapka OTP 265819 hai. Bank karamchari kabhi OTP nahi maangte."),
        ("hinglish", 0, "banking_otp", "INR 899.00 ke online payment ke liye OTP 618304 daalein. Yeh code kisi ko forward mat karo."),
        ("hinglish", 0, "banking_otp", "Aapke Banyan Bank mobile app login ka verification code 754029 hai. Valid for 5 mins. Kisi ko mat batana."),
        ("hinglish", 0, "banking_otp", "UPI registration ke liye aapka 6-digit OTP 389142 hai. Agar aapne request nahi ki to is SMS ko ignore karein."),
        ("hinglish", 0, "banking_otp", "Deccan Bank: Rs. 425.00 card purchase ke liye OTP 501728 hai. Kripya apna OTP gupt rakhein."),

        # 5. UPI confirmation (5)
        ("hinglish", 0, "upi_confirmation", "UPI se Rs. 140.00 Gupta Dairy ko safaltapoorvak payment hua. UPI Ref 432501928374. A/c XX8201."),
        ("hinglish", 0, "upi_confirmation", "Aapko UPI dwara Sunita se INR 1,250.00 mile hain. A/c XX6305 mein jama ho gaye hain."),
        ("hinglish", 0, "upi_confirmation", "Rs. 680.00 Bharat Gas bill UPI se chukaya gaya. UPI Ref No 532590182734. Avl Bal Rs. 11,400.00."),
        ("hinglish", 0, "upi_confirmation", "Aapke A/c XX2918 se INR 220.00 UPI payment Metro Bookshop ko poora hua on 19-Nov-26."),
        ("hinglish", 0, "upi_confirmation", "UPI AutoPay dwara INR 149.00 mobile recharge safal hua. A/c XX4105."),

        # 6. Balance notification (4)
        ("hinglish", 0, "balance_notification", "Balance jaankari: Aaj 20-Nov-26 ko aapke khate XX8201 mein kul INR 34,650.00 bache hue hain."),
        ("hinglish", 0, "balance_notification", "Mini statement A/c XX4912: Aapka clear balance Rs. 17,900.50 hai."),
        ("hinglish", 0, "balance_notification", "Banyan Bank balance soochna: Aapke khate XX2094 mein aaj Rs. 24,810.00 uplabdh hain."),
        ("hinglish", 0, "balance_notification", "Aapke A/c XX5108 ka end-of-day balance INR 19,320.75 hai. Dhanyavaad."),

        # 7. Institutional / everyday (4)
        ("hinglish", 0, "institutional_notice", "College notice: Semester 5 ke practical exam ki date notice board par laga di gayi hai."),
        ("hinglish", 0, "institutional_notice", "Library reminder: Aapki kitab Friday tak wapas karni hai, campus desk par jama kar dein."),
        ("hinglish", 0, "institutional_notice", "Hostel soochna: Kal shaam 6 baje common room mein general meeting hogi."),
        ("hinglish", 0, "institutional_notice", "Clinic update: Aapki kal subah 10 baje ki doctor appointment confirm hai."),

        # ---------- SCAM ENGLISH (40) ----------
        # 1. Fake bank account blocking (8)
        ("english", 1, "scam_account_block", "URGENT: Your Orion Bank A/c XX7301 will be blocked today by 8 PM. Click https://orion-kyc-fix.example immediately to prevent suspension."),
        ("english", 1, "scam_account_block", "Final Warning: Your savings account has been placed on hold due to incomplete verification. Reactivate now at https://bit.ly/acct-unblock-26."),
        ("english", 1, "scam_account_block", "Dear Customer, your debit card and netbanking will be deactivated tonight. Verify immediately at http://bank-reactivate-desk.example."),
        ("english", 1, "scam_account_block", "Security Alert: Your Harbor Bank account is temporarily frozen. Call immediately on 9811223344 and verify account details to unblock."),
        ("english", 1, "scam_account_block", "Account Suspension Notice: Outgoing transactions on your bank A/c are restricted. Unlock within 1 hour at https://tinyurl.com/unfreeze-bank."),
        ("english", 1, "scam_account_block", "Your mobile banking profile will be permanently closed today unless you complete urgent verification at https://mybank-verify-now.example."),
        ("english", 1, "scam_account_block", "Warning: Bank account compromised. Freeze will be applied in 30 mins unless you confirm details at https://secure-bank-restore.example."),
        ("english", 1, "scam_account_block", "Your Valley Bank credit card has been suspended for compliance failure. Reactivate immediately via https://card-restore-portal.example."),

        # 2. Requests to share OTPs or PINs (8)
        ("english", 1, "scam_otp_pin", "Bank Fraud Team: An unauthorized transaction of INR 14,900 was initiated. Share your 6-digit OTP right now to stop the debit."),
        ("english", 1, "scam_otp_pin", "Dear Customer, reply immediately with the OTP received on your phone to complete your bank refund of Rs. 5,400."),
        ("english", 1, "scam_otp_pin", "Card Protection Desk: Please send your 4-digit ATM PIN and verification code so we can unblock your debit card immediately."),
        ("english", 1, "scam_otp_pin", "Urgent Bank Call Follow-up: Tell us the one-time password sent just now to reverse the duplicate charge on A/c XX5027."),
        ("english", 1, "scam_otp_pin", "To activate your new bank card limit of Rs. 2,00,000, provide your OTP and MPIN to our support officer right now."),
        ("english", 1, "scam_otp_pin", "Your UPI refund of INR 2,750 is stuck. Enter your UPI PIN and share the OTP to receive money into your account."),
        ("english", 1, "scam_otp_pin", "Bank Security Verification: Send the 6-digit code and ATM PIN immediately or your account will remain frozen."),
        ("english", 1, "scam_otp_pin", "Merchant reversal desk: Provide the OTP you just received so Rs. 8,200 can be credited back to your bank account."),

        # 3. Fake KYC updates (8)
        ("english", 1, "scam_fake_kyc", "Dear Customer, your bank KYC expired today. Update KYC immediately at https://instant-bank-ekyc.example to avoid account freeze."),
        ("english", 1, "scam_fake_kyc", "PAN card linkage failed on your savings A/c. Complete e-KYC within 24 hours at https://bit.ly/pan-bank-update or account will be blocked."),
        ("english", 1, "scam_fake_kyc", "Urgent Compliance Alert: Your Aadhaar KYC is pending with the bank. Open https://aadhaar-kyc-bank.example and submit details now."),
        ("english", 1, "scam_fake_kyc", "Your bank account will be restricted from tomorrow due to overdue KYC. Verify identity immediately at https://tinyurl.com/ekyc-urgent."),
        ("english", 1, "scam_fake_kyc", "Mandatory Bank KYC Re-verification: Click https://kyc-compliance-bank.example right now and upload PAN to prevent deactivation."),
        ("english", 1, "scam_fake_kyc", "Dear Account Holder, your netbanking KYC status is invalid. Update your KYC details today at https://bank-kyc-fix.example."),
        ("english", 1, "scam_fake_kyc", "Notice: Savings account KYC not updated. Avoid immediate block by completing verification at https://quick-kyc-desk.example."),
        ("english", 1, "scam_fake_kyc", "Final KYC Reminder: Your bank A/c outgoing transfers will stop tonight. Confirm KYC at https://verify-ekyc-now.example immediately."),

        # 4. Suspicious links claiming to represent banks (8)
        ("english", 1, "scam_bank_link", "Orion Bank Rewards: Your 14,500 loyalty points worth INR 7,250 expire tonight. Redeem cash instantly at https://bit.ly/orion-points-cash."),
        ("english", 1, "scam_bank_link", "Bank Income Tax Refund of INR 16,800 approved for A/c XX7301. Claim directly at https://bank-tax-credit.example today."),
        ("english", 1, "scam_bank_link", "Dear Customer, your pre-approved personal loan of Rs. 5,00,000 is ready. Log in at https://instant-bank-loan.example to disburse now."),
        ("english", 1, "scam_bank_link", "Harbor Bank Security Update: Install the mandatory bank security app from https://tinyurl.com/bank-shield-apk to avoid block."),
        ("english", 1, "scam_bank_link", "Your credit card annual fee waiver of Rs. 2,500 is pending. Click https://waive-card-fee-bank.example and verify card immediately."),
        ("english", 1, "scam_bank_link", "Important Bank Notice: View your frozen e-statement and release pending funds at https://statement-unlock-bank.example."),
        ("english", 1, "scam_bank_link", "Valley Bank Cashback: Claim INR 3,900 bonus credit before midnight at https://claim-bank-bonus.example."),
        ("english", 1, "scam_bank_link", "Your bank UPI ID is flagged for review. Open https://upi-bank-verify.example right now to prevent deactivation."),

        # 5. Urgent requests for banking credentials (8)
        ("english", 1, "scam_credentials", "Urgent Bank Verification: Enter your 16-digit debit card number, expiry date, and CVV at https://card-confirm-now.example to unblock."),
        ("english", 1, "scam_credentials", "Your netbanking password has expired. Log in with your user ID and password at https://netbank-reset-now.example immediately."),
        ("english", 1, "scam_credentials", "Bank Dispute Desk: Provide your card number, CVV, and ATM PIN right now to reverse the unauthorized INR 11,500 charge."),
        ("english", 1, "scam_credentials", "Security Upgrade Required: Submit your banking login credentials and MPIN at https://bank-upgrade-auth.example within 1 hour."),
        ("english", 1, "scam_credentials", "Dear Cardholder, confirm your CVV and netbanking passcode by replying to this alert so we can lift the hold on your card."),
        ("english", 1, "scam_credentials", "Urgent: Your bank account requires immediate password and PIN verification at https://bit.ly/bank-auth-fix to prevent closure."),
        ("english", 1, "scam_credentials", "To claim your INR 4,200 bank interest credit, enter your debit card details and CVV at https://interest-credit-bank.example."),
        ("english", 1, "scam_credentials", "Final Alert: Send your netbanking login ID, password, and OTP immediately to stop permanent deactivation of your account."),

        # ---------- SCAM HINGLISH (40) ----------
        # 1. Fake account blocking (8)
        ("hinglish", 1, "scam_account_block", "Urgent: Aapka Lotus Bank khata aaj shaam ko block ho jayega. Turant https://lotus-kyc-unblock.example par verify karo."),
        ("hinglish", 1, "scam_account_block", "Antim chetavni: Aapka savings account freeze kar diya gaya hai. Chalu rakhne ke liye abhi https://bit.ly/khata-chalu kholein."),
        ("hinglish", 1, "scam_account_block", "Priya grahak, aapka debit card aur netbanking aaj raat deactivate ho jayega. Turant https://card-chalu-bank.example par update karein."),
        ("hinglish", 1, "scam_account_block", "Bank alert: Aapke account par rok laga di gayi hai. Unblock karwane ke liye turant 9811445566 par call karein aur details dein."),
        ("hinglish", 1, "scam_account_block", "Aapka Banyan Bank khata 2 ghante mein suspend hoga. Rokne ke liye https://tinyurl.com/bank-khata-fix par login karo."),
        ("hinglish", 1, "scam_account_block", "Aapka mobile banking band hone wala hai. Abhi https://mobile-bank-unblock.example kholkar apna account verify karein."),
        ("hinglish", 1, "scam_account_block", "Jaldi dhyan dein: Aapke bank A/c ki outgoing seva band ho jayegi agar aapne aaj verification nahi kiya at https://bank-seva-now.example."),
        ("hinglish", 1, "scam_account_block", "Aapka credit card block kar diya gaya hai. Turant reactivate karne ke liye https://card-verify-turant.example par click karo."),

        # 2. OTP / PIN share requests (8)
        ("hinglish", 1, "scam_otp_pin", "Bank fraud desk: Aapke khate se Rs. 15,000 ka galat debit rokne ke liye aaya hua OTP turant bhejo."),
        ("hinglish", 1, "scam_otp_pin", "Aapka Rs. 4,800 ka bank refund pending hai. Paise lene ke liye apna 6-digit OTP aur UPI PIN abhi share karein."),
        ("hinglish", 1, "scam_otp_pin", "Bank support: Aapka ATM card unblock karne ke liye apna ATM PIN aur OTP abhi reply mein bhejein."),
        ("hinglish", 1, "scam_otp_pin", "Jaldi batao: Aapke phone par jo verification code aaya hai woh share karo taaki galat transaction cancel ho sake."),
        ("hinglish", 1, "scam_otp_pin", "Aapke bank reward Rs. 3,500 khate mein bhejne ke liye apna MPIN aur OTP turant batao."),
        ("hinglish", 1, "scam_otp_pin", "Card department se soochna: Naya card chalu karne ke liye apna PIN aur aaya hua OTP abhi send karo."),
        ("hinglish", 1, "scam_otp_pin", "Aapka UPI payment atka hua hai, turant refund paane ke liye UPI PIN aur OTP yahan share karein."),
        ("hinglish", 1, "scam_otp_pin", "Bank manager bol raha hoon, aapka account freeze hone se bachane ke liye OTP turant bhejo."),

        # 3. Fake KYC updates (8)
        ("hinglish", 1, "scam_fake_kyc", "Priya grahak, aapka bank KYC aaj expire ho gaya hai. Turant https://bank-ekyc-turant.example par update karein warna khata block hoga."),
        ("hinglish", 1, "scam_fake_kyc", "Aapke bank A/c mein PAN link nahi hai. 24 ghante mein https://bit.ly/pan-bank-kyc par KYC poora karo nahi to khata band hoga."),
        ("hinglish", 1, "scam_fake_kyc", "Aadhaar KYC pending hone ke karan aapka bank account suspend hone wala hai. Abhi https://aadhaar-kyc-fix.example par verify karo."),
        ("hinglish", 1, "scam_fake_kyc", "Zaroori soochna: Bank KYC update na karne par aaj raat se ATM aur UPI band hoga. Click https://tinyurl.com/kyc-seva-now."),
        ("hinglish", 1, "scam_fake_kyc", "Aapke Deccan Bank khate ka KYC fail ho gaya hai. Turant https://deccan-kyc-update.example par PAN aur details bharein."),
        ("hinglish", 1, "scam_fake_kyc", "Bank KYC re-verification zaroori hai. Account bachane ke liye abhi https://kyc-verify-khata.example kholein."),
        ("hinglish", 1, "scam_fake_kyc", "Jaldi karo: Aapka netbanking KYC adhoora hai, aaj shaam tak https://netbank-kyc-now.example par update karo."),
        ("hinglish", 1, "scam_fake_kyc", "Aapke savings A/c ka KYC samapt ho raha hai. Block se bachne ke liye https://quick-ekyc-bank.example par click karein."),

        # 4. Suspicious links claiming to represent banks (8)
        ("hinglish", 1, "scam_bank_link", "Lotus Bank reward: Aapke Rs. 6,500 ke reward points aaj khatam honge. Cash lene ke liye abhi https://bit.ly/bank-points-le kholein."),
        ("hinglish", 1, "scam_bank_link", "Aapke bank khate mein Rs. 12,000 ka tax refund manzoor hua hai. Claim karne ke liye https://tax-refund-bank.example par login karein."),
        ("hinglish", 1, "scam_bank_link", "Pre-approved bank loan Rs. 4,00,000 bina kagaz ke! Abhi https://fast-bank-loan.example par click karke paise paayein."),
        ("hinglish", 1, "scam_bank_link", "Bank suraksha alert: Naya security app https://tinyurl.com/bank-app-apk se download karo warna netbanking band hoga."),
        ("hinglish", 1, "scam_bank_link", "Aapke credit card ki annual fee Rs. 1,999 maaf karwane ke liye abhi https://card-fee-maaf.example par verify karein."),
        ("hinglish", 1, "scam_bank_link", "Aapka bank cashback Rs. 2,900 ready hai! Turant claim karne ke liye https://bank-cashback-le.example kholein."),
        ("hinglish", 1, "scam_bank_link", "Aapka ruka hua bank statement aur paisa kholne ke liye https://bank-statement-open.example par abhi login karo."),
        ("hinglish", 1, "scam_bank_link", "Jaldi approve karo: Aapke bank UPI par Rs. 5,000 ka prize collect request aaya hai at https://upi-prize-bank.example."),

        # 5. Urgent credential requests (8)
        ("hinglish", 1, "scam_credentials", "Urgent bank alert: Apna 16-digit debit card number, expiry aur CVV abhi https://card-verify-abhi.example par daalein."),
        ("hinglish", 1, "scam_credentials", "Aapka netbanking password expire ho gaya hai. Khata bachane ke liye https://password-reset-bank.example par login ID aur password enter karo."),
        ("hinglish", 1, "scam_credentials", "Bank helpdesk: Rs. 9,000 ka galat charge wapas lene ke liye apna card number, CVV aur ATM PIN turant bhejein."),
        ("hinglish", 1, "scam_credentials", "Bank security update ke liye apna MPIN aur netbanking passcode abhi https://bank-mpin-update.example par submit karo."),
        ("hinglish", 1, "scam_credentials", "Aapka card hold par hai. Unblock karne ke liye CVV, expiry aur PIN reply mein turant bhejo."),
        ("hinglish", 1, "scam_credentials", "Turant dhyan dein: Khata band hone se rokne ke liye https://bit.ly/bank-pass-fix par apna password aur PIN verify karo."),
        ("hinglish", 1, "scam_credentials", "Bank interest bonus Rs. 3,200 paane ke liye apna debit card number aur CVV https://bonus-card-bank.example par daalo."),
        ("hinglish", 1, "scam_credentials", "Antim soochna: Apna banking login password, MPIN aur OTP abhi bhejein nahi to account hamesha ke liye band hoga."),
    ]

    rows = []
    for idx, (lang, label, cat, txt) in enumerate(items, 1):
        rows.append({
            "id": f"v3h{idx:03d}",
            "text": normalize_sms(txt),
            "label": label,
            "language": lang,
            "family": f"v3_holdout_{lang}_{cat}_{idx:03d}",
            "category": cat,
            "source": "synthetic_v3_holdout_independent",
        })
    return rows


def main() -> None:
    v2_dev = read_jsonl(ROOT / "data/synthetic/v2_development.jsonl")
    v3_added = _make_dev_families()
    v3_dev = v2_dev + v3_added
    v3_holdout = _make_holdout_dataset()

    # 1. Verify internal development integrity (no cross-split leakage or near-duplicates)
    check_leakage(v3_dev)
    dev_groups = group_near_duplicates(v3_dev)
    near_split = {}
    for row, g in zip(v3_dev, dev_groups):
        if g in near_split and near_split[g] != row["split"]:
            raise ValueError(f"Cross-split near-duplicate in v3_development: {row['id']} ({row['split']} vs {near_split[g]})")
        near_split[g] = row["split"]

    # 2. Verify ZERO leakage or near-duplicates between v3_holdout and (v3_dev + v2_holdout + UCI splits)
    v2_holdout = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    uci_all = []
    for sp in ("train", "calibration", "validation", "test"):
        p = ROOT / f"data/processed/{sp}.jsonl"
        if p.exists():
            uci_all.extend(read_jsonl(p))

    combined = []
    for r in v3_dev:
        combined.append({"id": r["id"], "text": r["text"], "split": "dev"})
    for r in v2_holdout:
        combined.append({"id": r["id"], "text": r["text"], "split": "v2_holdout"})
    for r in uci_all:
        combined.append({"id": r["id"], "text": r["text"], "split": "uci"})
    for r in v3_holdout:
        combined.append({"id": r["id"], "text": r["text"], "split": "v3_holdout"})

    # Canonical exact check
    seen_canon = {}
    for r in combined:
        c = canonical(r["text"])
        if c in seen_canon and seen_canon[c][0] != r["split"]:
            if "v3_holdout" in (seen_canon[c][0], r["split"]):
                raise ValueError(f"Exact duplicate with v3_holdout: {r['id']} vs {seen_canon[c]}")
        seen_canon[c] = (r["split"], r["id"])

    # Near-duplicate cosine >= 0.90 check involving v3_holdout
    all_groups = group_near_duplicates(combined)
    group_members: dict[str, list[tuple[str, str]]] = {}
    for r, g in zip(combined, all_groups):
        group_members.setdefault(g, []).append((r["split"], r["id"]))
    leaks = []
    for g, members in group_members.items():
        splits = {sp for sp, _ in members}
        if "v3_holdout" in splits and len(splits) > 1:
            leaks.append(members)
    if leaks:
        raise ValueError(f"Near-duplicate leakage with v3_holdout: {leaks[:5]}")

    write_jsonl(ROOT / "data/synthetic/v3_development.jsonl", v3_dev)
    write_jsonl(ROOT / "data/synthetic/v3_holdout.jsonl", v3_holdout)

    print(json.dumps({
        "v3_development_total": len(v3_dev),
        "v3_dev_splits": {f"{sp}:{lbl}": cnt for (sp, lbl), cnt in sorted(Counter((r["split"], r["label"]) for r in v3_dev).items())},
        "v3_holdout_total": len(v3_holdout),
        "v3_holdout_lang_label": {f"{lg}:{lbl}": cnt for (lg, lbl), cnt in sorted(Counter((r["language"], r["label"]) for r in v3_holdout).items())},
        "leakage_and_near_dup_audit": "PASSED (0 overlaps)",
    }, indent=2))


if __name__ == "__main__":
    main()
