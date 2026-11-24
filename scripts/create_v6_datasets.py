"""Create strictly family-separated V6 synthetic development and fresh unseen V6 holdout datasets.

Preserves all V1/V2/V3/V4/V5 datasets untouched. Enforces zero family overlap, zero exact text overlap,
entity firewalls, and zero cross-partition char 3-5-gram near-duplicates (>= 0.85 cosine similarity)
across V6 dev splits, V6 holdout, V5 holdout, V4 holdout, V3 holdout, V2 holdout, indian_sms,
UCI processed splits, and reproduced failure strings.
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


def _build_v6_development_additions() -> list[dict]:
    """Add family-separated EN/HI cases targeting contrast-pivot scams, Hinglish recharges, self-entry passcodes, and auto-reversals."""
    specs = [
        # --- TRAIN BENIGN ---
        ("train", "hinglish", 0, "v6_tr_hi_telecom_pack", [
            "Metro Mobile recharge update: Aapka 35 GB data aur unlimited voice pack agle 28 din ke liye activate ho gaya hai.",
            "Horizon Telecom plan confirmation: Rs. 299 ka monthly prepaid data aur call combo aaj safaltapoorvak chalu ho chuka hai.",
            "Pinnacle Fiber bill desk: Aapka broadband aur unlimited data tariff 30 din ke liye renew kar diya gaya hai; raseed portal par dekhein.",
            "Oakwood Mobile alert: Aapke prepaid number par 1.5 GB rozana data aur roaming pack agle 84 din tak sakriya ho gaya hai.",
            "Cedar Telecom soochna: Postpaid plan mein 40 GB rollover data aur call pack joda gaya hai, koi aur karwai zaroori nahi.",
        ]),
        ("train", "english", 0, "v6_tr_en_passcode_reversal", [
            "Harbor Bank verification: Enter passcode 684210 inside your own mobile app to confirm recurring utility mandate.",
            "Banyan Coop confirmation: Key in single-use passcode 519044 in official app settings to approve standing biller setup.",
            "Solstice Card reversal confirmation: Duplicate POS swipe of INR 2,780.00 dropped off automatically without calling helpline.",
            "Oakwood Credit billing update: An overlapping merchant pre-auth of Rs. 1,940.00 rolled back cleanly onto statement without user steps.",
            "Evergreen Pay app setup: Type temporary passcode 304918 strictly inside mobile banking screen to link autopay mandate.",
        ]),
        # --- TRAIN SCAM (short crisp warning-then-request pivots EN + HI) ---
        ("train", "english", 1, "v6_tr_en_warn_pivot_short", [
            "Keep your PIN confidential from third parties. However, send your OTP right now to settle your refund.",
            "Never disclose passcodes to outsiders. Yet reply with your 6-digit OTP immediately to finalize cashback credit.",
            "Do not give OTPs to unknown callers. Still, forward your verification OTP now to process this reversal.",
            "Security rule warns never pass your PIN; nevertheless, type back your 6-digit OTP right away to unlock payout.",
            "Always protect your card passcode from others. However, provide the SMS OTP right now to release your rebate.",
            "Never reveal login passwords to strangers; even so, text back your 6-digit verification code now for fee refund.",
        ]),
        ("train", "hinglish", 1, "v6_tr_hi_warn_pivot_short", [
            "Apna OTP anjaan logon ko kabhi mat batana. Lekin apna refund paane ke liye SMS OTP abhi bhej do.",
            "Kisi ko apna secret PIN share na karein; phir bhi cashback confirm karne ke liye 6-digit code turant reply karo.",
            "Bank rules kehte hain password gupt rakhein. Magar kati hui rakam wapas lene ke liye OTP abhi forward kar do.",
            "Anjaan vyakti ko apna verification token na dein; parantu atka paisa khate mein dalwane turant OTP bhejein.",
        ]),

        # --- CALIBRATION ---
        ("calibration", "hinglish", 0, "v6_cal_hi_telecom_pack", [
            "Horizon Mobile recharge soochna: Aapka 24 GB high-speed data aur unlimited call plan agle 56 din ke liye sakriya hai.",
            "Metro Fiber update: Rs. 599 ka monthly prepaid data pack bina kisi rukawat ke aaj renew ho gaya hai.",
        ]),
        ("calibration", "english", 0, "v6_cal_en_passcode_reversal", [
            "Meridian Trust confirmation: Enter passcode 820419 inside your own mobile banking portal to save trusted biller.",
            "Crestline Card reversal note: Duplicate retail POS swipe of INR 2,190.00 dropped off automatically with no call needed.",
        ]),
        ("calibration", "english", 1, "v6_cal_en_warn_pivot_short", [
            "Never hand your OTP to strangers. Still, send back the 6-digit OTP right now to settle your refund.",
            "Do not expose your card passcode to callers. However, reply with your verification OTP now to claim cash.",
        ]),
        ("calibration", "hinglish", 1, "v6_cal_hi_warn_pivot_short", [
            "Kisi ko apna SMS passcode mat dena. Lekin ruka hua refund release karne ke liye OTP abhi bhej do.",
        ]),

        # --- VALIDATION ---
        ("validation", "hinglish", 0, "v6_val_hi_telecom_pack", [
            "Cedar Mobile prepaid alert: Aapka 60 GB internet aur calling pack agle 28 din ke liye safaltapoorvak chalu ho gaya hai.",
            "Oakwood Telecom update: Rs. 479 ka unlimited call aur rozana data plan aaj aapke number par activate kar diya gaya.",
        ]),
        ("validation", "english", 0, "v6_val_en_passcode_reversal", [
            "Harbor Trust confirmation: Enter passcode 471920 inside your own official mobile application to authorize mandate.",
            "Banyan Card adjustment: Duplicate hotel POS swipe of INR 4,120.00 rolled back cleanly without calling support.",
        ]),
        ("validation", "english", 1, "v6_val_en_warn_pivot_short", [
            "Always keep OTPs private from strangers. However, send your OTP immediately so your rebate settles.",
            "Never give security tokens over chat. Yet reply with your 6-digit verification code now to unlock refund.",
        ]),
        ("validation", "hinglish", 1, "v6_val_hi_warn_pivot_short", [
            "Anjaan vyakti ke saath OTP share mat karein. Phir bhi reward refund confirm karne ke liye code abhi bhej do.",
        ]),
    ]

    rows = []
    idx = 1
    for split, lang, label, family, texts in specs:
        for text in texts:
            rows.append({
                "id": f"v6d{idx:03d}",
                "split": split,
                "label": label,
                "language": lang,
                "family": family,
                "source": "synthetic_v6_dev",
                "text": text,
            })
            idx += 1
    return rows


def build_v6_holdout() -> list[dict]:
    """Build fresh unseen 240 labeled (120 EN, 120 HI) + 24 ambiguous holdout messages.

    Uses 100% fresh unseen entities: Tungabhadra Bank, Sabarmati Trust, Periyar Pay, Konark Card,
    Vellore Mart, Gomti Express, Sutlej Power, Beas Water, Nilachal Rail, Zanskar Telecom,
    Mandovi Fin, Shivalik Hospital.
    """
    specs = [
        # ==================== ENGLISH BENIGN (60 = 10 categories x 6) ====================
        ("english", 0, "otp_delivery", "v6h_en_otp", "ctrl6_otp_1", [
            "Use single-use OTP 408291 to unlock your Tungabhadra Bank portal statement. Treat this number strictly confidential.",
            "Sabarmati Trust alert: Temporary code 715930 generated for INR 1,340.00 spend at Vellore Mart. Never give to any caller.",
            "391847 is your login code for Konark Card settings inside Periyar Pay. Helpline staff never request this figure.",
            "Periyar Pay one-time token 628194 expires inside four minutes. Guard privately at every step.",
            "Tungabhadra Bank verification: Type passcode 590283 strictly within our mobile banking screen to save your electricity payee.",
            "Transaction OTP 847205 issued against Sutlej Power bill Rs. 760.00 on Konark Debit XX6180. Refuse callers asking for digits.",
        ]),
        ("english", 0, "fraud_awareness", "v6h_en_awareness", None, [
            "Tungabhadra Security Bulletin: Swindlers circulate bogus debit freeze scares and clone verification portals. Team members never request passwords or PINs.",
            "Sabarmati Cyber Advisory: Impostors mask caller IDs claiming overdue PAN validation or blocked cards. Never disclose CVV numbers.",
            "Periyar Pay Safety Tip: Cheaters bait holders using incoming collect prompts disguised as lottery prizes. Keep in mind no PIN authorizes receiving money.",
            "Konark Card Caution Note: Disregard alerts pushing instant web-link verification. Service representatives never instruct customers to speak security digits aloud.",
            "Digital hygiene alert: Do not click short web URLs pressing sudden e-KYC upload; open your banking app directly to check messages.",
            "Tungabhadra awareness: Protect against remote desktop tricks—avoid installing viewer utilities or reading verification tokens to callers claiming reversals.",
        ]),
        ("english", 0, "debit_credit_receipt", "v6h_en_tx_receipt", None, [
            "Tungabhadra Bank: Credited savings account XX3719 by INR 19,200.00 via NEFT Ref TB4491820. Clear Bal INR 54,890.00.",
            "Sabarmati Alert: Debit of Rs. 1,625.00 recorded on A/c XX9204 at Vellore Mart on 22-Nov-26. Helpline 1800-420-9911 if unrecognized.",
            "Konark Credit Card XX4815 charged INR 2,410.00 at Gomti Express Cargo on 21-Nov-26. Remaining credit headroom Rs. 96,500.00.",
            "Payroll deposit: Account ending 3719 with Tungabhadra received INR 44,000.00 through IMPS Ref 881029475612.",
            "Purchase alert: Nilachal Rail ticket Rs. 830.00 paid by Sabarmati debit card XX7031 on 21-Nov-26.",
            "Semi-annual savings yield: Mandovi Fin credited INR 468.90 interest directly into account XX6045.",
        ]),
        ("english", 0, "failed_payment_reversal", "v6h_en_reversal", "ctrl6_refund_1", [
            "Tungabhadra Settlement: Declined Vellore Mart charge of Rs. 1,180.00 reversed cleanly into A/c XX3719 without further steps.",
            "Sabarmati Auto-Credit: Failed Nilachal Rail ticket sum INR 940.00 returned straight to savings balance; no approval code required.",
            "Periyar Pay reversal update: Unsuccessful UPI debit of INR 1,870.00 deposited automatically back to linked bank funds.",
            "Vellore Mart refund status: Rs. 790.00 for returned kitchen item settled cleanly to card account ending 9204.",
            "Gomti Express reimbursement: INR 1,540.00 towards voided shipping label posted into Tungabhadra savings A/c XX3719.",
            "Konark Card billing reversal: Overlapping POS charge of Rs. 2,840.00 dropped off statement balance automatically without calling support.",
        ]),
        ("english", 0, "user_card_block", "v6h_en_user_block", "ctrl6_block_1", [
            "Tungabhadra Confirmation: Swipe card XX4815 was permanently locked after your mobile app request. Call 1800-420-9911 only if unintended.",
            "Sabarmati Trust: As initiated by your login session, debit card XX9204 has been disabled; reorder plastic inside Card Management.",
            "Periyar Card settings: You paused contactless spend and froze ATM card XX7031 inside app controls; resume anytime yourself.",
            "Mandovi Fin status: Missing card XX6045 locked per your phone request cleanly; replacement envelope arrives in five days.",
            "Konark Card update: Manual in-app block submission for debit card XX6180 finished smoothly with zero extra follow-up.",
            "Sabarmati record: Customer-initiated card pause on ending 7031 completed; support callers never request PINs to reactivate.",
        ]),
        ("english", 0, "branch_kyc_appointment", "v6h_en_branch_kyc", None, [
            "Tungabhadra Branch Desk: Periodic KYC renewal slot confirmed at Adyar branch on 11-Dec-26 at 10:15 AM.",
            "Sabarmati Trust: Your counter appointment at Civil Lines branch for annual Know Your Customer verification is booked on 12-Dec-26 at noon; bring original ID.",
            "Record confirmation: Submitted KYC forms at Tungabhadra Cantonment branch passed check cleanly with nothing pending.",
            "Konark counter update: Appreciation for visiting Malleswaram branch; identity papers reviewed and marked current in records.",
            "Mandovi Fin booking: Assigned counter seat #07 at Ellis Bridge branch for scheduled yearly KYC desk review on 14-Dec-26.",
            "Periyar Trust status: Periodic KYC review lodged at local counter finished verification properly.",
        ]),
        ("english", 0, "statement_notification", "v6h_en_statement", None, [
            "Tungabhadra monthly PDF: November passbook statement for A/c XX3719 ready inside https://docs.tungabhadra.example/statements/nov.",
            "Sabarmati e-statement: Access your quarterly checking ledger online through https://portal.sabarmati.example/passbook.",
            "Konark Card cycle bill: Statement for XX4815 archived securely at https://billing.konarkcard.example/invoice.",
            "Mandovi Fin annual note: Fee summary and interest sheet available at https://archive.mandovifin.example/fees.",
            "Zanskar Telecom invoice: Monthly bill #ZT61904 worth Rs. 549.00 published at https://bills.zanskartel.example/pdf.",
            "Periyar savings document: Q2 TDS tax certificate uploaded to https://tax.periyarpay.example/tds-q2.",
        ]),
        ("english", 0, "upi_notification", "v6h_en_upi", None, [
            "Periyar Pay alert: Transferred INR 610.00 from Tungabhadra A/c XX3719 to Shivalik Hospital Medical. Ref 772910384612.",
            "Through Sabarmati UPI rail: Received INR 1,420.00 directly into customer account ending 9204 (UTR 581029384712).",
            "Remitted Rs. 880.00 neatly using Periyar handle towards Beas Water Store on 22-Nov-26. Ref #441928374610.",
            "Tungabhadra UPI credit: Rs. 2,350.00 received from S. Menon into XX3719. Check balance inside official app.",
            "Power board UPI confirmation: Sutlej Power received INR 1,290.00 successfully via Txn Ref 661029384712.",
            "Monthly auto-debit: Zanskar Telecom recurring Rs. 349.00 settled cleanly from Sabarmati A/c XX9204.",
        ]),
        ("english", 0, "balance_notification", "v6h_en_balance", None, [
            "Tungabhadra savings balance: Cleared funds inside A/c XX3719 at end of day 22-Nov-26 stand at INR 54,890.00.",
            "Sabarmati balance update: Checking A/c XX9204 holds Rs. 33,140.50 available balance as of morning sync.",
            "Konark Card headroom: Remaining spending balance on XX4815 sits at Rs. 96,500.00 against Rs. 1,20,000.00 sanctioned limit.",
            "Mandovi Fin summary: Account XX6045 carries INR 18,450.00 cleared cash with zero uncleared instruments.",
            "Periyar Pay ledger: Available wallet funds equal INR 3,190.00. Review complete breakdown inside app.",
            "Tungabhadra OD snapshot: Drawn principal INR 0.00, unutilized standby line INR 40,000.00.",
        ]),
        ("english", 0, "delivery_utility_benign", "v6h_en_utility", None, [
            "Vellore Mart courier alert: Order #VM77210 moved via Gomti Express and delivers tomorrow evening. Check merchant tab for live status.",
            "Sutlej Power confirmation: Payment Rs. 1,640.00 credited to Consumer #SP44091. Next reading scheduled 22-Dec-26.",
            "Shivalik Hospital front desk: Physiotherapy consultation set Saturday 04:00 PM with Dr. Rao; carry lab summary.",
            "Beas Water receipt: Monthly tap water bill Rs. 380.00 cleared cleanly under Account BW20419. Zero balance remaining.",
            "Nilachal Rail update: Coach S5 Seat 18 confirmed aboard Express 18402 departing Thursday 06:40 AM.",
            "Zanskar Telecom notification: Monthly 45 GB mobile data pack refreshed cleanly for next 28-day validity.",
        ]),

        # ==================== ENGLISH SCAM (60 = 10 categories x 6) ====================
        ("english", 1, "account_block_threat", "v6h_en_block", "ctrl6_block_1", [
            "URGENT Tungabhadra alert: Your savings account freezes midnight! Click https://bit.ly/tunga-unlock immediately to prove identity.",
            "Sabarmati security alert: Debit card XX9204 deactivated after foreign login! Sign in at https://sabarmati-unblock.example right now to prevent closure.",
            "Konark Card warning: Credit line suspends permanently inside 2 hours unless reactivated at https://t.co/konark-verify.",
            "Mandovi Fin restriction: A/c XX6045 placed on hold! Reply urgently with full card number and CVV to prevent shutdown.",
            "CRITICAL Periyar Pay notice: Wallet access deactivates tonight unless credentials updated on https://tinyurl.com/periyar-sec.",
            "Tungabhadra card emergency: ATM facility temporarily locked! Text back PIN and birth date right now to unblock.",
        ]),
        ("english", 1, "otp_pin_solicitation", "v6h_en_otp", "ctrl6_otp_1", [
            "Tungabhadra Desk: Send your 6-digit OTP right now so support halts an unauthorized debit of Rs. 6,200.00.",
            "Sabarmati fraud unit calling: Reply with ATM PIN and CVV immediately to reverse wrong merchant deduction.",
            "Konark Support team: Message back 4-digit MPIN together with verification code urgently to stop points expiry.",
            "Protect passwords from callers cleanly. Yet reply with your 6-digit OTP immediately so our refund settles.",
            "Periyar Helpdesk: Forward the 6-digit SMS security token right away to authorize higher wallet limit.",
            "Never tell strangers secret PINs; however, send back verification OTP right now to claim halted bonus.",
        ]),
        ("english", 1, "fake_kyc_link", "v6h_en_kyc", None, [
            "Tungabhadra customer alert: KYC verification lapsed! Visit https://bit.ly/tunga-kyc inside two hours else netbanking cuts off.",
            "Sabarmati e-KYC warning: Submit Aadhaar and PAN particulars via https://sabarmati-ekyc.example right away to escape freeze.",
            "Konark Credit notice: Re-verify KYC details urgently at https://tinyurl.com/konark-kyc or card closes tonight.",
            "Mandovi KYC portal: Enter login password and PAN details promptly at https://mandovi-kyc-fix.example to continue transfers.",
            "Periyar Trust alert: Re-KYC failed validation; tap https://rb.gy/periyar-ekyc immediately so salary credits do not reject.",
            "Sabarmati compliance emergency: Finish KYC recheck tonight urgently or online banking shuts permanently at midnight.",
        ]),
        ("english", 1, "fake_refund", "v6h_en_refund", "ctrl6_refund_1", [
            "Vellore Mart refund ready cleanly: Approve incoming collect notification worth INR 1,180 right away inside UPI app to deposit funds into A/c XX3719.",
            "Gomti Express rebate Rs. 2,150 approved for transit delay: Accept pending collect popup immediately and confirm UPI PIN.",
            "Sutlej Power double-bill return INR 1,640 queued! Confirm payment collect prompt on Periyar Pay using PIN to pull funds.",
            "Konark annual charge refund Rs. 999 sanctioned—tap Authorize on our incoming collect popup immediately for credit.",
            "Keep account secrets away from third parties; however, accept this Rs. 1,700 collect request now to settle overcharge.",
            "Nilachal Rail cancellation payout INR 1,450 cleared: Approve payment collect request promptly to move money into balance.",
        ]),
        ("english", 1, "read_aloud_otp", "v6h_en_read_aloud", None, [
            "Billing team calling: Rs. 3,599 annual membership charge hits Konark Card today. Speak the 6-digit reversal code aloud on call right now.",
            "Tungabhadra security desk: We sent an abort passcode to block rogue withdrawal. Read out every digit of that security code aloud now.",
            "Audit helpdesk calling: Dictate the single-use confirmation code just texted so we stop an INR 4,700 deduction.",
            "Dispute resolution agent regarding Rs. 2,950 wrong fee: Read aloud the SMS security token over voice immediately.",
            "Auto-debit cancellation unit: Card bills Rs. 1,899 inside 5 minutes—speak out the confirmation code delivered to inbox aloud right now.",
            "Fraud unit reminder: Never share secrets loosely, yet dictate your 6-digit abort OTP aloud over this call right now to halt theft.",
        ]),
        ("english", 1, "family_transfer_urgent", "v6h_en_family", None, [
            "Hey bro, stuck outside highway toll gate with dead battery and borrowing stranger's phone hotspot. Transfer 3,700 rs via UPI right away, voice drops here.",
            "Mom my regular SIM crashed during storm and I need INR 7,900 wired urgently to pay hospital counter; avoid calling back, 1 percent battery left.",
            "Dad texting from classmate's handset because mine fell and shattered outside hostel. Send Rs. 5,800 urgently via Periyar UPI right now, mic is broke.",
            "Auntie lost my main phone at metro gate and using guard's backup number. Kindly transfer INR 4,400 immediately to this wallet handle, can't answer calls inside ward.",
            "Sis urgent—SIM card died outstation and texting off driver's spare phone. Wire Rs. 5,100 right now to this QR ID, speak once back.",
            "Ma borrowing co-worker's device after mine stopped charging at station. Please send INR 6,800 urgently via UPI for rail booking, do not ring this line.",
        ]),
        ("english", 1, "delivery_customs_scam", "v6h_en_delivery", None, [
            "Gomti Express Customs alert: Foreign parcel stopped at cargo terminal; pay INR 680 duty on https://bit.ly/gomti-duty before auction.",
            "Vellore Logistics notice: House address unclear on parcel #VL8021—update pin code and pay Rs. 40 redelivery fee via https://gomti-rebook.example now.",
            "Urgent customs release notice: Courier faces return tonight! Clear INR 850 duty tax at https://tinyurl.com/cargo-duty right away.",
            "Express depot alert: Unpaid storage fee Rs. 490 overdue on docket; remit via https://rb.gy/depot-pay before 5 PM.",
            "Final attempt from Gomti Dispatch: Verify tracking PIN and submit INR 260 re-route charge at https://dispatch-rebook.example immediately.",
            "Import clearance threat: Parcel halted over missing KYC—upload ID and Rs. 720 tariff via https://parcel-customs.example urgently.",
        ]),
        ("english", 1, "prize_lottery_scam", "v6h_en_prize", None, [
            "WINNER ALERT! Your mobile won Tungabhadra Grand Lucky Draw INR 6,50,000! Claim immediately at https://bit.ly/tunga-prize.",
            "Periyar Diwali Draw: Selected winner of Rs. 45,000 gift voucher + smartphone! Remit Rs. 499 shipping charge at https://periyar-claim.example.",
            "Konark Card Cashback Jackpot: INR 30,000 reward expires midnight—open https://tinyurl.com/konark-cash and confirm card CVV.",
            "Zanskar Telecom Lucky Draw: You grabbed laptop + Rs. 1,10,000 prize! Settle handling fee right away via https://t.co/zanskar-win.",
            "Sabarmati Mega Raffle: INR 2,00,000 payout waiting under your number—enter A/c details and Rs. 999 GST fee on https://sabarmati-win.example.",
            "Festival jackpot INR 16,500 cleared inside Periyar Pay! Submit UPI PIN via https://rb.gy/fest-claim today.",
        ]),
        ("english", 1, "job_scam", "v6h_en_job", None, [
            "Remote product tagging part-time role! Zero experience required, earn INR 3,500 daily via Telegram desk—join now with Rs. 950 onboarding deposit.",
            "Work-from-home store rating job vacancy: Make Rs. 2,500–4,600 daily! Message Telegram coordinator immediately and pay Rs. 750 slot kit fee.",
            "Online survey verification job hiring today! Guaranteed Rs. 3,100 daily wage; visit https://bit.ly/task-kit to purchase starter pass.",
            "URGENT brand promoter part-time opening: Daily income INR 4,200 off mobile; contact Telegram trainer and remit Rs. 899 registration fee.",
            "Boutique travel portal seeking freelance reviewers! Daily salary Rs. 3,700; send Rs. 1,050 toolkit deposit via https://tinyurl.com/work-pass.",
            "Immediate digital assistant job hiring at Vellore Partner Desk! Earn Rs. 2,900 daily; transfer Rs. 650 security fee to activate tasks.",
        ]),
        ("english", 1, "utility_disconnect_scam", "v6h_en_utility_scam", None, [
            "URGENT Sutlej Power notice: Home power cuts off tonight at 9:30 PM over unverified previous bill. Call engineer 9811445566 immediately.",
            "Beas Water shutoff warning: Residential tap connection ends today—update bill receipt on https://bit.ly/beas-stay right away.",
            "Sutlej Power Board Alert: Meter suspension slated tonight; share UPI PIN or support token with helpline 9700445566 right now.",
            "DISCONNECT WARNING from Power Desk: Last invoice missing ledger entry! Open https://tinyurl.com/sutlej-cut immediately to halt disconnection.",
            "Zanskar Telecom barring alert: Primary SIM disconnects permanently within 3 hours! Call officer 9822667788 urgently.",
            "Municipal meter cut-off notice: Clear INR 18 balancing fee immediately at https://rb.gy/power-stay or face blackout tonight.",
        ]),

        # ==================== HINGLISH BENIGN (60 = 10 categories x 6) ====================
        ("hinglish", 0, "otp_delivery", "v6h_hi_otp", "ctrl6_hi_otp_1", [
            "Aapke Periyar Pay profile verify karne ke liye 528194 one-time code bheja gaya hai; yeh kisi ko bol kar ya text par na batayein.",
            "Sabarmati Trust internet login ka OTP 739205 hai; koi phone par adhikari ban kar maange tab bhi mat batana.",
            "Konark Card shopping INR 1,410.00 ke liye SMS code 418920 bheja gaya hai. Apna passcode aur password hamesha niji rakhein.",
            "Vellore Mart online bill INR 890.00 jama karne ke liye OTP 604819 apni screen par daalein. Yeh code kisi ko forward mat karo.",
            "Tungabhadra NEFT payee approval ka gopniya code 927104 bheja gaya hai; phone par kisi anjaan ko mat dein.",
            "Sutlej bijli bill Rs. 760.00 bharne ke liye Periyar verification OTP 318204 aaya hai; call karne walon ko hargiz na batayein.",
        ]),
        ("hinglish", 0, "fraud_awareness", "v6h_hi_awareness", None, [
            "Periyar Pay savdhani: Khate mein paise aane par kabhi UPI PIN bharna ya collect notification accept karna zaroori nahi hota.",
            "Tungabhadra Bank jaagrukta: Koi vyakti galat charge wapas karne ke bahane mobile par aaya code sunane ko kahe to turant phone rakh dein.",
            "Sabarmati Trust niyam: Apna netbanking password aur 6-ankon ka token sada gupt rakhein; bank kabhi calls par KYC nahi poochta.",
            "Konark cyber suraksha: Anjaan chhote links par click kar ke PAN ya KYC verify karne se bachein; asli update app mein hi milta hai.",
            "Mandovi Fin sandesh: Screen share karne wale apps kabhi download na karein aur kisi anjaan ko cashback ke naam par OTP na dein.",
            "Chetavani soochna: Nakli khata band hone ke sandesh ya jhoothi call par vishwas na karein aur official helpline check karein.",
        ]),
        ("hinglish", 0, "debit_credit_receipt", "v6h_hi_tx_receipt", None, [
            "Tungabhadra Bank update: Khata XX3719 mein NEFT dwara Rs. 14,500.00 credit hue hain. Uplabdh balance INR 54,890.00 hai.",
            "Sabarmati Trust: Card XX9204 se Vellore Mart par Rs. 1,290.00 aur travel par Rs. 410.00 kharch hue. Balance app mein dekhein.",
            "Konark Card XX4815 dwara Gomti Express par INR 2,410.00 ka payment safal raha. Baki seema Rs. 96,500.00 hai.",
            "Mandovi savings khate mein Rs. 5,200.00 jama hue aur naye IMPS Ref 772910384612 ki pushti ho chuki hai.",
            "Shivalik Hospital par Sabarmati debit card XX7031 se Rs. 840.00 kate gaye; anjaan kharch lagne par bank helpline mein phone karein.",
            "Tungabhadra savings A/c XX3719 mein taimahi byaj ke Rs. 468.90 jama kar diye gaye hain.",
        ]),
        ("hinglish", 0, "failed_payment_reversal", "v6h_hi_reversal", "ctrl6_hi_refund_1", [
            "Periyar Pay auto-refund: Fail hui Rs. 1,180.00 ki rashi wapas aapke Tungabhadra khate mein laut aayi hai; koi approval nahi chahiye.",
            "Vellore Mart cancel order ke Rs. 790.00 aapke Sabarmati account mein seedhe aa gaye hain, UPI PIN daalne ki zaroorat nahi.",
            "Nilachal Rail ticket radd hone par kata hua Rs. 940.00 balance mein wapas jama ho chuka hai; kisi link par tap na karein.",
            "Konark Card par double kati rashi Rs. 2,840.00 aapke agle mahine ke billing ledger mein khud adjust ho gayi hai.",
            "Sutlej bijli transaction radd hone se Rs. 1,290.00 wapas khata ending 3719 mein deposit ho gaye hain.",
            "Gomti parcel booking cancel karne par refund Rs. 1,540.00 aapke linked source account mein aa gaya hai.",
        ]),
        ("hinglish", 0, "user_card_block", "v6h_hi_user_block", "ctrl6_hi_block_1", [
            "Tungabhadra mobile app mein aapne khud apna debit card XX4815 lock kar diya hai; anjaan hone par 1800-420-9911 par call karein.",
            "Sabarmati Trust notice: Aapke nirdesh par ATM card XX9204 permanently band kar diya gaya hai.",
            "Periyar Card settings: Official app ke Card Control mein ja kar aapne khud swipe aur international card XX7031 freeze kiya hai.",
            "Card khone par aapke request par Mandovi debit card XX6045 block kar diya gaya hai; naya card ghar aayega.",
            "Konark app confirmation: Aapne apna credit card XX6180 temporarily pause kiya hai aur jab chahein wapas on kar sakte hain.",
            "Sabarmati app se aapne apna debit card khud hi band kar diya hai; dobara chalu karne ke liye branch ya official portal dekhein.",
        ]),
        ("hinglish", 0, "branch_kyc_appointment", "v6h_hi_branch_kyc", None, [
            "Sabarmati Trust note: Branch par jama aapki KYC file poori tarah update aur approved ho chuki hai, koi kaam baaki nahi.",
            "Tungabhadra Bank soochna: Adyar branch par aapka routine KYC renewal appointment 11-Dec ko subah 10:15 AM scheduled hai.",
            "Konark desk: Branch counter par aapne jo KYC papers aur ID proof diye woh verify ho kar record mein current mark ho gaye hain.",
            "Mandovi Fin branch desk: Ellis Bridge branch mein annual KYC check ke liye aapka counter slot number 07 Somwar ko book hua hai.",
            "Periyar Trust: Counter par jama ki gayi aapki KYC verification safaltapoorvak samaapt ho gayi hai, reply karne ki zaroorat nahi.",
            "Tungabhadra reminder: Alag branch counter par kal dopahar original photo ID saath le kar aayein.",
        ]),
        ("hinglish", 0, "statement_notification", "v6h_hi_statement", None, [
            "Tungabhadra savings khate ka pichle mahine ka PDF statement https://docs.tungabhadra.example/statement par dekha ja sakta hai.",
            "Periyar Pay aur linked account ki pichle maah ki transaction report https://reports.periyarpay.example/ledger mein uplabdh hai.",
            "Sabarmati khata summary: Taimahi passbook aur interest sheet https://portal.sabarmati.example/passbook par taiyar hai.",
            "Konark Card billing summary aur PDF invoice https://billing.konarkcard.example/nov-pdf par upload kar di gayi hai.",
            "Mandovi khata statement aur annual TDS certificate https://archive.mandovifin.example/tds par download ke liye uplabdh hai.",
            "Zanskar Telecom postpaid monthly bill PDF https://bills.zanskartel.example/monthly par check karein.",
        ]),
        ("hinglish", 0, "upi_notification", "v6h_hi_upi", None, [
            "Periyar UPI update: Shivalik Pharmacy ko Rs. 580.00 bheje gaye aur UPI Ref 772910384612 darj hua.",
            "Tungabhadra aur Periyar wallet se Rs. 1,420.00 Sabarmati khate mein credit ho gaye hain. Khata ending 9204.",
            "Sutlej Power bijli aur utility bill ke Rs. 1,640.00 UPI Ref 581029384712 se safaltapoorvak jama ho gaye hain.",
            "Sabarmati Pay dwara Vellore Mart mein Rs. 740.00 ka payment poora raha. Naya balance app par check karein.",
            "Rakesh ji ko UPI se Rs. 920.00 bhejne par Tungabhadra A/c XX3719 debit hua aur ledger update ho gaya.",
            "Beas Jal bill ke Rs. 380.00 Periyar UPI dwara jama kar diye gaye hain. Ref 661029384712.",
        ]),
        ("hinglish", 0, "balance_notification", "v6h_hi_balance", None, [
            "Tungabhadra savings A/c XX3719 mein aaj din khatam hone par uplabdh balance INR 54,890.00 aur hold rashi shunya hai.",
            "Sabarmati khata XX9204 ka taja clear balance Rs. 33,140.50 hai. Poora vivran official app mein dekhein.",
            "Konark Card XX4815 par abhi Rs. 96,500.00 ki credit seema shesh hai; agli bill tareekh 12-Dec hai.",
            "Periyar Pay aur linked savings khate ka kul uplabdh balance INR 3,190.00 darj kiya gaya hai.",
            "Mandovi account balance summary: Aapke khate XX6045 mein Rs. 18,450.00 safe aur uplabdh hain.",
            "Tungabhadra recurring deposit aur savings balance aaj subah app ledger mein update ho chuka hai.",
        ]),
        ("hinglish", 0, "delivery_utility_benign", "v6h_hi_utility", None, [
            "Vellore Mart courier parcel Gomti Express se nikal chuka hai aur kal shaam tak ghar pahunchega. Tracking app mein dekhein.",
            "Sutlej bijli board: Consumer #SP44091 par Rs. 1,640.00 aur meter shulk jama ho gaya hai. Agla bill agle maah aayega.",
            "Shivalik Hospital reception: Shanivar shaam 04:00 PM Dr. Rao ke saath aapka checkup tay hai, purani reports saath lana.",
            "Beas Water bill Rs. 380.00 poori tarah jama ho chuka aur koi pichla bakaya nahi bacha hai.",
            "Zanskar Telecom notification: Aapka 45 GB data aur calling plan agle 28 din ke liye recharge aur chalu ho gaya hai.",
            "Nilachal Rail jaankari: Guruwar subah 06:40 AM train mein aapki seat S5-18 confirm ho gayi hai. Shubh yatra!",
        ]),

        # ==================== HINGLISH SCAM (60 = 10 categories x 6) ====================
        ("hinglish", 1, "account_block_threat", "v6h_hi_block", "ctrl6_hi_block_1", [
            "Tungabhadra urgent warning: Aaj raat aapka savings khata band ho jayega! Turant https://bit.ly/tunga-block par KYC update karein.",
            "Sabarmati ATM card XX9204 block ho raha hai—bachne ke liye abhi https://sabarmati-unlock.example khol kar card details bharein.",
            "Konark Credit card 2 ghante mein deactivate ho jayega! Turant https://t.co/konark-kyc par ja kar MPIN verify karein.",
            "Periyar Pay suraksha alert: Khatre ke kaaran khata aaj block kiya jayega, https://tinyurl.com/periyar-unfreeze khol kar turant PIN confirm karein.",
            "Mandovi bank khata suraksha khatre mein hai; band hone se bachane abhi card number aur CVV message mein bhejein.",
            "Tungabhadra netbanking aaj raat band ho rahi hai! Chalu rakhne helpline 9811445566 par turant ATM PIN batayein.",
        ]),
        ("hinglish", 1, "otp_pin_solicitation", "v6h_hi_otp", "ctrl6_hi_otp_1", [
            "Tungabhadra desk: Aapke khate se Rs. 6,200 katne wala hai, rokne ke liye SMS par aaya 6-digit OTP turant bhej do.",
            "Sabarmati card care: Apna ATM PIN aur CVV abhi share karo taaki aapke card par laga extra shulk cancel ho sake.",
            "Konark executive bol raha hoon: Credit limit badhane ke liye phone par aaya OTP aur janm-tareekh turant reply karein.",
            "Apna secret password hamesha gupt rakhein, magar Rs. 2,800 bonus lene ke liye SMS OTP abhi bhej do.",
            "Periyar team: Wallet limit update poori karne ke liye mobile mein aaya OTP aur MPIN turant reply karein.",
            "Rules kehte hain anjaan ko OTP mat batana; lekin ruka hua cashback pane ke liye apna verification code abhi batao.",
        ]),
        ("hinglish", 1, "fake_kyc_link", "v6h_hi_kyc", None, [
            "Sabarmati bank grahak chetavani: Jaldi online KYC verify karo nahi to aaj raat aapki netbanking band ho kar ruk jayegi.",
            "Tungabhadra e-KYC alert: Turant https://bit.ly/tunga-ekyc par PAN jodein warna khata hamesha ke liye freeze ho jayega.",
            "Konark PAN verification baaki hai! https://tinyurl.com/konark-pan khol kar aaj hi details bharo warna card block hoga.",
            "Mandovi KYC desk: Shaam 6 baje se pehle https://mandovi-ekyc.example par login aur Aadhaar number submit karo warna paisa atak jayega.",
            "Periyar KYC warning: Aapka wallet verification fail ho gaya; abhi https://rb.gy/periyar-kyc khol kar dobara chalu karein.",
            "Tungabhadra final reminder: Emergency KYC aaj raat khatam ho rahi hai, turant netbanking aur card number SMS se bhej dein.",
        ]),
        ("hinglish", 1, "fake_refund", "v6h_hi_refund", "ctrl6_hi_refund_1", [
            "Vellore Mart return pass ho gaya: Khate mein Rs. 1,180 wapas lene ke liye app ke andar collect notification turant approve karein aur PIN daalein.",
            "Gomti Express delay ke Rs. 2,150 jama hone wale hain; Periyar app par aayi collect request accept karo taaki paisa khate mein aaye.",
            "Overcharge katoti ke 1,640 rupaye wapas lene ke liye aayi hui UPI collect request accept karo aur apna secret PIN bharo.",
            "Shivalik hospital billing rebate Rs. 1,500 lene ke liye turant incoming collect prompt authorize karein.",
            "Zanskar recharge cashback Rs. 1,150 jama karwane ke liye screen par dikh rahi payment collect request abhi accept karein.",
            "Kisi ko secret token mat batana, par atki Rs. 2,700 rashi khate mein paane ke liye payment prompt par abhi approve dabao.",
        ]),
        ("hinglish", 1, "read_aloud_otp", "v6h_hi_read_aloud", None, [
            "Konark billing desk se bol raha hoon, card par 3,599 ka galat renewal kat raha hai; reverse ke liye aaya code abhi padh kar sunao.",
            "Tungabhadra security unit: Debit card par Rs. 4,700 ka videshi charge laga hai, rokne ke liye mobile par aaya code turant bol kar batao.",
            "Galat shulk wapas dilane ke liye aapke phone par jo verification code aaya hai woh bina ruke abhi padh kar suna do.",
            "Membership team se call hai—aaj Rs. 2,299 katne wale hain; cancel karwane ke liye SMS wala 6-digit code abhi bol kar sunao.",
            "Khate par galat insurance fee Rs. 2,999 jud gayi hai, turant hatane ke liye message wala security code dictate karo.",
            "Suraksha niyam bolta hai OTP mat do, lekin ruka paisa wapas dalwane ke liye SMS code phone par abhi padh kar sunao.",
        ]),
        ("hinglish", 1, "family_transfer_urgent", "v6h_hi_family", None, [
            "Bhaiya toll naka ke paas phans gaya, mera handset band ho gaya aur anjaan bande ka wifi hotspot le kar msg kar raha hoon. Abhi 3700 rs UPI par wire karein.",
            "Maa baarish mein meri SIM aur display kharab ho gayi; ticket lene ke liye turant 7800 rs transfer kar do, battery 1% par hai call mat karna.",
            "Papa dost ke doosre phone se likh raha hoon kyunki mera phone station par chhoot gaya. Clinic jama ke liye abhi 8100 rupaye send karo, ring mat karna.",
            "Didi mera mobile toot gaya hai aur mic bilkul band hai. Dawai ke liye 4400 rs abhi is QR UPI par bhej dein, ghar aakar settlement karta hoon.",
            "Chacha wallet aur purana phone bazar mein ghum ho gaya, guard ke number se message bhej raha hoon. Jaldi 5300 rs is account par bhejo, hospital mein call mat lagana.",
            "Mummy train chhootne wali hai aur phone hang ho gaya, bagal wale ke number se msg kiya hai. Turant 5900 rs is UPI ID par transfer karo.",
        ]),
        ("hinglish", 1, "delivery_customs_scam", "v6h_hi_delivery", None, [
            "Gomti Express customs warning: Aapka bahar se aaya courier airport par ruka hai; aaj Rs. 680 duty https://bit.ly/gomti-duty par bharo.",
            "Vellore parcel hold: Ghar ka pata adhoora hai—re-delivery ke liye https://gomti-track.example khol kar Rs. 40 card se jama karein.",
            "Courier company aakhri soochna: Packet aaj wapas ja raha hai! Turant https://tinyurl.com/cargo-clear par address verify karein.",
            "Import shulk Rs. 850 baaki hone se parcel ruka hai; abhi https://rb.gy/cargo-pay par bhejo warna zapt ho jayega.",
            "Delivery boy contact nahi kar pa raha, GPS update aur Rs. 150 charge ke liye https://vellore-ship.example link kholein.",
            "Foreign gift parcel chhudwane ke liye Rs. 950 clearance charge abhi https://t.co/cargo-gift par transfer karein.",
        ]),
        ("hinglish", 1, "prize_lottery_scam", "v6h_hi_prize", None, [
            "BADHAI! Aapke mobile number ne Tungabhadra Bumper Draw mein Rs. 6,00,000 jeeta hai! Claim karne abhi https://bit.ly/tunga-win kholein.",
            "Periyar festive inaam Rs. 65,000 + smart TV nikla hai! Delivery ke liye Rs. 499 fee https://periyar-draw.example par bhejo.",
            "Konark reward lucky draw mein Rs. 35,000 cash reward mila—claim karne https://tinyurl.com/konark-inaam par card details daalein.",
            "Zanskar Telecom lucky draw winner! Rs. 1,15,000 aur phone jeetne par turant Rs. 899 GST fee https://t.co/zanskar-inaam par jama karein.",
            "Sabarmati Jackpot Rs. 2,50,000 aaj lapse ho jayega; bank A/c aur PIN https://sabarmati-lotto.example par abhi verify karein.",
            "Diwali bonus Rs. 18,000 khate mein lene ke liye https://rb.gy/fest-spin par UPI PIN enter karo.",
        ]),
        ("hinglish", 1, "job_scam", "v6h_hi_job", None, [
            "Ghar baithe retail listing part-time kaam! Telegram par roz 3400 rupaye payout milega—abhi join karein aur Rs. 950 starter kit fee jama karein.",
            "Online phone rating job offer: Bina kisi interview daily Rs. 2600 kamayein! Abhi Telegram join kar ke Rs. 750 slot kit deposit bhejo.",
            "Work from home product tagging bharti! Rozana Rs. 3100 khate mein; start karne https://bit.ly/task-kit par Rs. 850 jama karein.",
            "Part-time social promoter job vacancy! Daily kamayi INR 4000 phone se; Telegram trainer ko msg kar ke Rs. 900 registration bhejein.",
            "Vellore Partner digital review work: Roz 2 ghante mein Rs. 2900 pay; ID chalu karwane Rs. 650 security fee turant bhejo.",
            "Travel site review work: Guarantee Rs. 3600 daily income; turant https://tinyurl.com/work-pass par Rs. 1,050 kit charge bhejein.",
        ]),
        ("hinglish", 1, "utility_disconnect_scam", "v6h_hi_utility_scam", None, [
            "Sutlej Power urgent notice: Pichla bijli bill update na hone se aaj raat 9:30 PM par connection katega. Turant 9811445566 par officer se baat karein.",
            "Beas Water vibhag warning: Ghar ka jal connection aaj band ho raha hai; turant https://bit.ly/beas-unblock par bill verify karo.",
            "Smart meter disconnection alert! Chalu rakhne ke liye abhi https://tinyurl.com/sutlej-stay par Rs. 20 card se bharein.",
            "Zanskar mobile network chetavani: Aaj raat aapki outgoing seva aur SIM lock hone wali hai, rokne ke liye 9700445566 par code batayein.",
            "Electricity office final alert: Aaj raat light katne se bachne turant viewer app dal kar executive 9822667788 ko code batayein.",
            "Sutlej meter offline warning: Line band hone se pehle https://rb.gy/power-stay par consumer ID update karo.",
        ]),

        # ==================== AMBIGUOUS HOLDOUT (24 = 12 EN + 12 HI, label=None) ====================
        ("english", None, "ambiguous_callback", "v6h_en_ambig_cb", None, [
            "Hi, texting from reception desk regarding Wednesday's handover checklist; ring back once you arrive.",
            "Please return my call on this secondary extension regarding residential visitor parking tags.",
            "Hello, calling about the RO purifier filter visit requested yesterday; call back post 5 PM.",
            "Ping me on this number once you finish looking through the updated society bylaws PDF.",
        ]),
        ("english", None, "ambiguous_payment_reminder", "v6h_en_ambig_pay", None, [
            "Reminder that Rs. 1,550 toward this month's apartment corridor lighting maintenance pool falls due Saturday.",
            "Hey, Rs. 380 shared train cab split from Sunday evening remains unsettled; transfer whenever free.",
            "Clubhouse tennis pass renewal INR 600 may be settled at reception counter before Friday.",
            "Department lab manual printing share Rs. 450 per student is due ahead of Tuesday workshop.",
        ]),
        ("english", None, "ambiguous_sparse_link", "v6h_en_ambig_link", None, [
            "Posted updated residents gate pass register and committee minutes on https://soc-board.example/minutes.",
            "Table tennis weekend knockout bracket uploaded at https://tt-draw.example/weekend.",
            "Find revised seminar room floorplan and schedule on https://symposium.example/agenda.",
            "Building borewell pump service timings shared via https://soc-notice.example/timings.",
        ]),
        ("hinglish", None, "ambiguous_callback", "v6h_hi_ambig_cb", None, [
            "Bhaiya time milne par is number par callback kar dena, mangalwar event ke catering par charcha karni thi.",
            "Hello, aapke bike insurance renewal papers office mein rakhe hain; shaam ko ring kar lena.",
            "Zaroori baat karni thi, class se free ho kar ek baar is mobile par call lagana.",
            "Main gate par courier box rakha hai, receive karne ke liye guard bhai ko phone mila lo.",
        ]),
        ("hinglish", None, "ambiguous_payment_reminder", "v6h_hi_ambig_pay", None, [
            "Apartment generator diesel hissa Rs. 500 is Friday tak secretary office mein dene ka reminder hai.",
            "Kal shaam ke lunch aur juice ke Rs. 360 hisaab baaki hai, free ho kar settle kar dena.",
            "Gym locker fee renew karne ke Rs. 450 agle Somwar tak desk par jama kar dein.",
            "Outing bus seat advance Rs. 950 ka reminder—aaj raat tak final list taiyar karni hai.",
        ]),
        ("hinglish", None, "ambiguous_sparse_link", "v6h_hi_ambig_link", None, [
            "Volleyball Sunday league ka naya fixture https://club-match.example/sunday par upload hua hai.",
            "Apartment overhead tank safai timetable https://soc-notice.example/tank par check karein.",
            "Lecture series ke slides aur handouts https://campus-notes.example/docs par mil jayenge.",
            "Campus canteen ka agle mahine ka rate chart https://mess-list.example/menu par lag chuka hai.",
        ]),
    ]

    rows = []
    idx = 1
    for lang, label, category, family, pair_id, texts in specs:
        for text in texts:
            row = {
                "id": f"v6h{idx:03d}",
                "label": label,
                "language": lang,
                "category": category,
                "family": family,
                "source": "synthetic_v6_holdout",
                "text": text,
            }
            if pair_id is not None:
                row["pair_id"] = pair_id
            rows.append(row)
            idx += 1
    return rows


def main() -> None:
    v5_dev = read_jsonl(ROOT / "data/synthetic/v5_development.jsonl")
    v6_add = _build_v6_development_additions()
    v6_dev = v5_dev + v6_add
    v6_hold = build_v6_holdout()

    ids_dev = set()
    for r in v6_dev:
        assert r.get("split") in ("train", "calibration", "validation")
        assert r.get("label") in (0, 1)
        assert r["id"] not in ids_dev, f"Duplicate id {r['id']}"
        ids_dev.add(r["id"])
        r["text"] = normalize_sms(r["text"])
    check_leakage(v6_dev)

    ids_hold = set()
    for r in v6_hold:
        assert r.get("label") in (0, 1, None)
        assert r["id"] not in ids_hold, f"Duplicate holdout id {r['id']}"
        ids_hold.add(r["id"])
        r["text"] = normalize_sms(r["text"])

    assert sum(1 for r in v6_hold if r["label"] in (0, 1)) == 240
    assert sum(1 for r in v6_hold if r["label"] is None) == 24
    assert sum(1 for r in v6_hold if r["language"] == "english" and r["label"] == 0) == 60
    assert sum(1 for r in v6_hold if r["language"] == "english" and r["label"] == 1) == 60
    assert sum(1 for r in v6_hold if r["language"] == "hinglish" and r["label"] == 0) == 60
    assert sum(1 for r in v6_hold if r["language"] == "hinglish" and r["label"] == 1) == 60

    dev_fams_by_split = {
        sp: {r["family"] for r in v6_dev if r["split"] == sp}
        for sp in ("train", "calibration", "validation")
    }
    hold_fams = {r["family"] for r in v6_hold}
    for i, a in enumerate(("train", "calibration", "validation")):
        assert not (dev_fams_by_split[a] & hold_fams), f"Family overlap {a} vs holdout"
        for b in ("train", "calibration", "validation")[i + 1:]:
            assert not (dev_fams_by_split[a] & dev_fams_by_split[b]), f"Family overlap {a} vs {b}"

    external_rows = []
    for tag, rel in (
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

    # Entity firewall across dev, V4, V5, and V6 holdouts
    v6_hold_brands = (
        "tungabhadra", "sabarmati", "periyar", "konark", "vellore", "gomti",
        "sutlej", "beas", "nilachal", "zanskar", "mandovi", "shivalik",
    )
    v5_hold_brands = (
        "narmada", "vindhya", "satpura", "coromandel", "yamuna mart", "tapi express",
        "cauvery", "mahanadi", "sahyadri", "chinar", "brahmaputra", "aravalli",
    )
    v4_hold_brands = ("kaveri", "deccan", "nilgiri", "saffron", "malabar", "tamarind", "chambal", "konkan", "palash", "godavari")

    v6_add_blob = " \n ".join(r["text"].lower() for r in v6_add)
    for b in v6_hold_brands + v5_hold_brands + v4_hold_brands:
        assert b not in v6_add_blob, f"Leaked holdout entity {b!r} in V6 dev additions!"

    v6_hold_blob = " \n ".join(r["text"].lower() for r in v6_hold)
    forbidden_in_v6_hold = (
        v5_hold_brands
        + v4_hold_brands
        + ("harbor bank", "solstice", "meridian", "evergreen", "crestline", "banyan coop", "oakwood", "cedar", "pinnacle", "sunrise mart", "horizon rail", "metro grid")
    )
    for b in forbidden_in_v6_hold:
        assert b not in v6_hold_blob, f"Leaked dev/prior-hold entity {b!r} in V6 holdout!"

    dev_canon = {canonical(r["text"]): r for r in v6_dev}
    hold_canon = {canonical(r["text"]): r for r in v6_hold}
    ext_canon = {canonical(r["text"]): r for r in external_rows}
    assert not (set(dev_canon) & set(hold_canon)), "Exact canonical overlap V6 dev vs V6 holdout!"
    assert not (set(dev_canon) & set(ext_canon)), f"Exact canonical overlap V6 dev vs ext: {set(dev_canon) & set(ext_canon)}"
    assert not (set(hold_canon) & set(ext_canon)), f"Exact canonical overlap V6 hold vs ext: {set(hold_canon) & set(ext_canon)}"

    tagged = (
        [{"id": r["id"], "partition": f"dev:{r['split']}", "text": r["text"]} for r in v6_dev]
        + [{"id": r["id"], "partition": "v6_hold", "text": r["text"]} for r in v6_hold]
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
        if len(parts_set) > 1 and any(item_id.startswith(("v6h", "v6d")) for item_id in ids):
            cross_hits.append(items)

    assert not cross_hits, f"V6 cross-partition near-duplicate collisions (>=0.85): {cross_hits}"

    dev_out = ROOT / "data/synthetic/v6_development.jsonl"
    hold_out = ROOT / "data/synthetic/v6_holdout.jsonl"
    write_jsonl(dev_out, v6_dev)
    write_jsonl(hold_out, v6_hold)

    summary = {
        "v6_development_sha256": digest(dev_out),
        "v6_holdout_sha256": digest(hold_out),
        "v6_dev_total": len(v6_dev),
        "v6_add_count": len(v6_add),
        "v6_dev_counts": {
            sp: {
                "total": sum(r["split"] == sp for r in v6_dev),
                "label_0": sum(r["split"] == sp and r["label"] == 0 for r in v6_dev),
                "label_1": sum(r["split"] == sp and r["label"] == 1 for r in v6_dev),
                "english": sum(r["split"] == sp and r["language"] == "english" for r in v6_dev),
                "hinglish": sum(r["split"] == sp and r["language"] == "hinglish" for r in v6_dev),
            }
            for sp in ("train", "calibration", "validation")
        },
        "v6_holdout_counts": {
            "total": len(v6_hold),
            "labeled": sum(r["label"] in (0, 1) for r in v6_hold),
            "ambiguous": sum(r["label"] is None for r in v6_hold),
            "english_0": sum(r["language"] == "english" and r["label"] == 0 for r in v6_hold),
            "english_1": sum(r["language"] == "english" and r["label"] == 1 for r in v6_hold),
            "hinglish_0": sum(r["language"] == "hinglish" and r["label"] == 0 for r in v6_hold),
            "hinglish_1": sum(r["language"] == "hinglish" and r["label"] == 1 for r in v6_hold),
        },
        "near_dup_cross_partition_085_v6_hits": len(cross_hits),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
