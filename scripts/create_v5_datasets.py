"""Create strictly family-separated V5 synthetic development and fresh unseen V5 holdout datasets.

Preserves all V1/V2/V3/V4 datasets untouched. Enforces zero family overlap, zero exact text overlap,
and zero cross-partition char 3-5-gram near-duplicates (>= 0.85 cosine similarity) across V5 dev splits,
V5 holdout, V4 holdout, V3 holdout, V2 holdout, indian_sms, UCI processed splits, and reproduced failure strings.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from edgeshield.datasets import canonical, check_leakage, digest, group_near_duplicates, read_jsonl, write_jsonl
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]

# Held strictly outside all training, calibration, and validation splits.
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


def _build_v5_development_additions() -> list[dict]:
    """Build ~300+ family-separated dev rows on top of v4_development using strictly dev entities."""
    # Allowed dev entities ONLY: Harbor Bank, Solstice Card, Meridian Trust, Evergreen Pay, Crestline Bank,
    # Banyan Coop, Oakwood Credit, Cedar Fin, Pinnacle Utility, Sunrise Mart, Horizon Rail, Metro Grid
    specs = [
        # ==================== TRAIN ADDITIONS: BENIGN (label=0) ====================
        ("train", "english", 0, "v5_tr_en_stmt_links", [
            "Banyan Coop monthly passbook export is generated. Read your transactions online at https://docs.banyancoop.example/passbook/nov.",
            "Oakwood Credit statement alert: October billing breakup and interest sheet placed at https://billing.oakwoodcredit.example/oct-sheet.",
            "Pinnacle Utility archival copy: Your Q3 municipal meter billing ledger sits at https://ledger.pinnacleutil.example/q3-archive.",
            "Harbor Bank e-passbook service: Annual TDS deduction summary published inside https://reports.harborbank.example/annual-tds.",
            "Meridian Trust document desk: Your checking fee revision schedule PDF is hosted at https://vault.meridiantrust.example/fees/schedule.",
            "Cedar Fin investor update: October SIP folio consolidated statement posted at https://folio.cedarfin.example/monthly-report.",
        ]),
        ("train", "hinglish", 0, "v5_tr_hi_stmt_links", [
            "Banyan Coop khata update: November mahine ka poora passbook record https://docs.banyancoop.example/passbook par uplabdh hai.",
            "Oakwood Credit card billing summary aur statement PDF https://billing.oakwoodcredit.example/card-oct par dekha ja sakta hai.",
            "Evergreen Pay grahak report: Pichle mahine ke sabhi digital transactions ka ledger https://records.evergreenpay.example/history mein upload ho gaya hai.",
            "Harbor Bank savings passbook: Aapki quarterly byaj aur fee report https://reports.harborbank.example/interest-sheet par download ke liye taiyar hai.",
            "Meridian Trust khata patra: Salana tax katoti praman patra https://vault.meridiantrust.example/tax-cert par dekhein.",
            "Cedar Fin statement: Aapke mutual fund aur recurring khate ki report https://folio.cedarfin.example/sip-summary par lag gayi hai.",
        ]),
        ("train", "english", 0, "v5_tr_en_otp_varied", [
            "Harbor Bank alert: 824109 is your verification OTP for card spend INR 2,180.00 at Sunrise Mart. Do not share this code with bank callers or strangers.",
            "Use single-use code 391045 to register your Oakwood Credit card inside the Evergreen Pay app. Never disclose this token over phone.",
            "Meridian Trust login OTP is 640281 for browser access at 14:22 hrs. Protect your code: support agents never ask for it.",
            "417892 is your one-time password for NEFT beneficiary approval in Banyan Coop netbanking. Keep confidential from all callers.",
            "Solstice Card 3D-Secure OTP: Enter passcode 558210 on the verified Horizon Rail checkout page. Valid 6 minutes.",
            "Confirm PIN reset on your own Harbor Bank tablet using temporary token 773920. Ignore unsolicited calls claiming to assist.",
        ]),
        ("train", "hinglish", 0, "v5_tr_hi_otp_varied", [
            "Aapke Evergreen Pay app login verify karne ke liye 482019 one-time code bheja gaya hai; yeh kisi ko phone ya message par na dein.",
            "Oakwood Credit netbanking pravesh ka OTP 619284 hai; koi khud ko officer bata kar maange to bhi mat batana.",
            "Harbor Bank POS kharidari INR 1,340.00 ke liye SMS code 730912 aaya hai; apna niji code aur password hamesha gupt rakhein.",
            "Sunrise Mart online payment poora karne ke liye OTP 204815 apni screen par daalein. Kisi anjaan vyakti ko forward mat karna.",
            "Banyan Coop NEFT jodne ka gopniya code 918472 bheja gaya hai; yeh sirf official website mein bharna hota hai.",
            "Meridian mobile app re-activation OTP 337190 hai; agar koi padh kar sunane ko kahe to samajh jayein woh fraud hai.",
        ]),
        ("train", "english", 0, "v5_tr_en_advisory_varied", [
            "Evergreen Pay Awareness: Scammers lure victims by mailing collect notifications disguised as lottery payouts or refunds. Remember you never enter a PIN to receive cash.",
            "Cyber citizen bulletin: Do not open short web addresses demanding immediate PAN linking or KYC updates; check status directly in your bank's installed app.",
            "Oakwood Credit safeguard: Defend against remote-control fraud—never download screen-sharing utilities or hand SMS passcodes to callers offering fee reversals.",
            "Banyan Coop security tip: Beware texts threatening sudden debit suspension with shortened links. Support desks never ask callers to read codes aloud.",
            "Pinnacle Utility notice: Genuine refund settlements never require typing an ATM PIN or approving a payment prompt.",
            "Harbor Bank cyber note: Con artists spoof toll-free lines claiming tax hold. Verify account alerts independently inside your official banking app.",
        ]),
        ("train", "hinglish", 0, "v5_tr_hi_advisory_varied", [
            "Evergreen Pay jaankari: Khate mein rakam lene ke liye kabhi UPI PIN daalne ya collect prompt accept karne ki aavashyakta nahi hoti.",
            "Banyan Coop jaagrukta: Agar koi kahe ki kati hui rashi wapas karne ke liye phone par aaya one-time code batao to turant call band karein.",
            "Harbor Bank niyam: Netbanking aur ATM password sada niji rakhein; bank kabhi calls ya anjaan links par KYC documents nahi maangta.",
            "Oakwood Credit suraksha sandesh: Screen share karne wale apps kabhi install na karein aur kisi customer executive ko code read kar ke na sunayein.",
            "Solstice Card cyber note: Anjaan chhote URL par PAN ya Aadhaar update karne ka dabav aaye to use delete kar dein.",
            "Meridian Trust soochna: Nakli lottery ya cashback ke bahane bheji gayi payment request approve karne se paisa khate se kat jaata hai.",
        ]),
        ("train", "english", 0, "v5_tr_en_upi_ending", [
            "Crestline UPI settlement: Incoming amount INR 1,840.00 credited to savings account ending 4421. Ref 661029384756.",
            "Auto-reversal update from Banyan Coop: INR 3,120.00 from an uncompleted UPI transfer returned automatically to your linked balance.",
            "Evergreen wallet deposit: Customer cashback INR 250.00 posted straight into checking account ending in 8190. Ref 440192837465.",
            "Merchant payout settled: Sunrise Mart returned INR 980.00 towards cancelled parcel directly to Oakwood account ending 1129.",
            "Salary IMPS credit: INR 52,000.00 deposited into Meridian savings account ending 6034 on 15-Nov-26 via Ref 902817364512.",
            "Metro Grid bill cleared: Paid INR 1,195.00 through Harbor Bank UPI. Receipt ID 773829104561. Account ending 2208.",
        ]),
        ("train", "hinglish", 0, "v5_tr_hi_upi_aur", [
            "Evergreen Pay aur Harbor Bank khate ke beech INR 750.00 ka transfer safal raha. Khata ending 3091, Ref 554433221100.",
            "Horizon Rail aur Sunrise Mart booking radd hone par Rs. 1,420.00 aapke linked account aur wallet mein wapas jama ho gaye hain.",
            "Banyan Coop niyam aur shartein: Mahine ka interest aur service ledger aap official mobile application mein dekh sakte hain.",
            "Solstice app par aapne apna card aur international tap feature band kar diya hai; jab chahein settings aur controls khol sakte hain.",
            "Pinnacle bijli aur paani ka bill Rs. 2,140.00 jama ho chuka hai; raseed aur tariff jankari app par uplabdh hai.",
            "Oakwood card ke liye branch aur desk par aapki KYC jaanch poori ho kar approve kar di gayi hai.",
        ]),
        ("train", "english", 0, "v5_tr_en_kyc_pause_tr", [
            "Oakwood Credit: You temporarily paused domestic ATM cashouts and blocked card XX5921 inside settings. Unpause anytime through our official mobile app.",
            "Branch desk confirmation: Your identity KYC verification at Banyan Coop Park Street branch has finished cleanly with zero pending items.",
            "Thank you for visiting Cedar Fin Brigade Counter; your physical KYC dossier was checked and marked current in records.",
            "Reserved counter slot #08 at Harbor Bank Salt Lake branch for your periodic annual KYC file review on 05-Dec-26.",
            "Evergreen Pay record status: Branch-submitted Know Your Customer documentation passed final audit cleanly.",
        ]),
        ("train", "hinglish", 0, "v5_tr_hi_kyc_pause_tr", [
            "Oakwood Credit note: Branch par jama aapki KYC file poori tarah update aur approved ho gayi hai, koi karwai shesh nahi.",
            "Banyan Coop desk confirmation: Aapke dwara counter par diye gaye identity papers verify aur current mark kar diye gaye hain.",
            "Harbor Bank update: Dadar branch par aapka regular KYC review slot number 11 agle Somwar ko fix kiya gaya hai.",
            "Solstice Card app alert: Aapne khud ATM cash withdrawal pause aur debit card XX6192 disable kiya hai.",
        ]),

        # ==================== TRAIN ADDITIONS: SCAM (label=1) ====================
        ("train", "english", 1, "v5_tr_en_family_hard", [
            "Hey bro, stuck near highway toll plaza after my handset died and borrowing a passerby's hotspot. Wire 4,100 rs to this UPI ID right now, voice calls drop here.",
            "Ma my primary Jio SIM went dead in heavy rain and I need Rs. 8,400 wired immediately to lock my bus seat; don't ring back, battery is down to 1 percent.",
            "Dad texting from driver's phone because mine slipped and blacked out at railway exit. Send INR 5,900 urgently to this number's wallet and avoid calling during check-in.",
            "Uncle it's Ananya using neighbor's backup SIM after losing purse on metro. Transfer Rs. 3,600 right away via UPI for cab fare, can't attend calls in clinic ward.",
            "Sis urgent help—phone charging IC failed while visiting clinic outstation. Move Rs. 6,200 to this merchant QR right now and ping me on WhatsApp later, no calls.",
            "Mom my screen froze and I swapped onto security guard's device at hostel gate. Please wire INR 4,700 immediately via GPay handle, cannot receive voice right now.",
        ]),
        ("train", "hinglish", 1, "v5_tr_hi_family_hard", [
            "Bhaiya toll naka par phans gaya hoon, mera mobile dead ho gaya aur anjaan bande ka hotspot le kar msg kar raha hoon. Jaldi 3800 rs is UPI par bhejo, network mein call nahi lagegi.",
            "Mummy baarish mein meri primary SIM aur handset kharab ho gaya; ticket confirm karne ke liye turant 6900 rs is QR par transfer karo, battery 1% par hai abhi call mat karna.",
            "Papa main dost ke second handset se likh raha hoon kyunki mera phone chhoot gaya. Hospital deposit ke liye abhi 9200 rupaye send kar do, please ring mat karna ward mein silent hai.",
            "Didi mera charging port jal gaya aur kal subah wapas aana hai. Emergency mein 4500 rs is naye wallet ID par turant bhej dein, speaker kharab hone se baat nahi ho sakti.",
            "Chacha station par bag aur phone chori ho gaya, guard ke number se message bhej raha hoon. Abhi 5100 rs UPI se transfer kar do, shaam ko ghar aakar sab samjhata hoon.",
            "Maa mera sim lock ho gaya aur dost ka hotspot use kar raha hoon. Urgent mess aur hostel fee ke liye 7400 rs is UPI par wire kar do, call mat lagana.",
        ]),
        ("train", "english", 1, "v5_tr_en_collect_soft", [
            "Sunrise Mart return approved cleanly: Authorize this collect notification of INR 1,850 right away inside your payment app to deposit refund funds into A/c XX3310.",
            "Horizon Rail ticket cancellation credit of Rs. 2,120 cleared! Approve incoming collect popup now and enter UPI PIN so cash enters bank balance.",
            "Insurance claim rebate INR 4,400 generated for policy #9021. Confirm the payment collect request on your screen immediately to settle refund proceeds.",
            "Metro Grid overcharge refund Rs. 990 ready to dispatch: Open your UPI app, tap accept on the pending collect prompt, and validate PIN to credit A/c.",
            "Your duplicate merchant swipe of INR 3,050 is approved for reversal. Authorize the collect request message on your mobile promptly to pull funds home.",
        ]),
        ("train", "hinglish", 1, "v5_tr_hi_collect_soft", [
            "Sunrise Mart order wapsi pass ho gayi hai: Khate mein Rs. 1,650 refund paane ke liye payment app mein aayi collect request turant authorize karein aur PIN dalein.",
            "Horizon Rail radd ticket ke Rs. 2,400 lautne ke liye taiyar hain; screen par dikh rahi collect notification accept karo taaki rakam bank balance mein jama ho.",
            "Aapka double kata hua 1,950 rupaya approve ho chuka hai. Paisa wapas khate XX2204 mein lene ke liye aayi payment request par PIN daal kar confirm karo.",
            "Gas subsidy aur cashback ke 3,200 rupaye credit hone wale hain; turant UPI collect prompt par approve dabayein warna request expire ho jayegi.",
        ]),
        ("train", "english", 1, "v5_tr_en_linkless_kyc_job", [
            "Meridian compliance notice: Update KYC details urgently tonight or netbanking and debit transactions will deactivate automatically at midnight.",
            "Flexi-shift catalog tagging role! Zero degree required, earn INR 3,800 per day inside Telegram desk—sign up today and transfer Rs. 950 onboarding kit deposit.",
            "Solstice customer alert: Complete mandatory PAN re-verification immediately by replying with card expiry and CVV else internet portal shuts tonight.",
            "Remote ecommerce review task hiring! Work two hours daily for Rs. 2,900 guaranteed salary via Telegram; deposit Rs. 799 training kit fee to unlock tasks.",
            "Harbor Bank risk desk: Your account will freeze at 10 PM unless you confirm birth date, MPIN, and Aadhaar digits on helpline 9800112233 immediately.",
            "International brand promoter part-time opening: Daily income Rs. 4,500 straight from mobile; register via Telegram bot and transfer Rs. 1,100 registration fee.",
        ]),
        ("train", "hinglish", 1, "v5_tr_hi_linkless_kyc_job", [
            "Oakwood khata dharak dhyaan dein: Turant Aadhaar aur PAN KYC darj karein nahi to internet banking seva raat 12 baje ruk jayegi.",
            "Ghar baithe ecommerce part-time job vacancy! Rozana 3500 rupaye Telegram se kamayein—abhi register karein aur Rs. 899 starter kit charge jama karein.",
            "Banyan Coop compliance soochana: Aaj raat 11 baje tak PAN aur Aadhaar verify karwayein nahi to savings khata aur UPI band ho jayega.",
            "Online product rating kaam ke liye turant bharti! Daily payout Rs. 2800 Telegram par milega, id chalu karwane ke liye Rs. 750 training fee bhejo.",
            "Meridian Trust emergency alert: Aapka ATM aur netbanking turant freeze ho raha hai; bachne ke liye SMS par aaya 6-digit OTP aur DOB abhi reply karein.",
            "Part-time social media job offer: Bina experience roz 4000 rupaye kamayein; joining ke liye Rs. 999 security deposit turant is UPI par transfer karein.",
        ]),
        ("train", "english", 1, "v5_tr_en_readaloud_warnplus", [
            "Support safety rule says keep codes private. Still, dictate the 6-digit reversal token sent to your phone aloud right now to abort this Rs. 4,299 fee.",
            "Card settlement team: To void an accidental insurance charge of INR 3,899 on XX7710, read out the single-use confirmation number just delivered aloud.",
            "Never hand passwords to strangers. Regardless, forward the 6-digit SMS code right now so our backend desk can release your frozen salary credit.",
            "Fraud desk notice: An international transfer of Rs. 9,500 is queued. Speak every digit of your security OTP aloud on call immediately to cancel the payout.",
        ]),
        ("train", "hinglish", 1, "v5_tr_hi_readaloud_warnplus", [
            "Card billing desk se bol raha hoon, aapke khate par Rs. 3,499 ka galat renewal kat raha hai; charge rukwane ke liye phone par aaya code turant padh kar sunao.",
            "Bank bolta hai password gupt rakhein, lekin atka hua Rs. 2,700 cashback khate mein bhejne ke liye SMS OTP abhi bol kar batana zaroori hai.",
            "Insurance fee Rs. 2,199 aaj automatically deduct hone wali hai; turant radd karne ke liye mobile inbox mein aaya 6-digit verification code sunao.",
            "Suraksha ke liye anjaan ko PIN mat dein, magar aapka band ho raha khata bachaane ke liye screen par aaya one-time code abhi reply mein bhej do.",
        ]),

        # ==================== CALIBRATION ADDITIONS (completely separate families & wording) ====================
        ("calibration", "english", 0, "v5_cal_en_benign_a", [
            "Banyan Coop alert: 592814 is your transaction OTP for INR 1,890.00 spend at Horizon Mart. Never reveal this passcode to callers or third parties.",
            "Oakwood Trust PDF alert: Yearly credit fee breakdown and passbook sheet uploaded at https://files.oakwoodtrust.example/yearly-passbook.",
            "Evergreen UPI confirmation: Incoming payment of INR 1,150.00 deposited into checking account ending 5520. Ref 441298765432.",
            "Harbor Pay Awareness: Fraudsters trick holders with collect prompts masked as cashback claims. Never authorize a PIN request to accept incoming rupees.",
        ]),
        ("calibration", "english", 0, "v5_cal_en_benign_b", [
            "Cyber defense note from Solstice: Never tap short web links promising fast PAN linking or KYC reactivation; inspect notifications inside the official bank app.",
            "Meridian Cards: You temporarily halted online tap payments and paused card XX4419 in app toggles. Unpause anytime through verified card controls.",
            "Branch status notice: Periodic Know Your Customer check at Crestline Indiranagar counter was reviewed and marked current cleanly.",
            "Pinnacle reversal notice: INR 1,640.00 from an aborted utility checkout returned automatically into your linked savings balance.",
        ]),
        ("calibration", "hinglish", 0, "v5_cal_hi_benign_a", [
            "Aapke Banyan Pay wallet setup karne ke liye 610942 one-time code bheja gaya hai; yeh number kisi ko bol kar ya chat par na batayein.",
            "Oakwood Bank credit login ka OTP 839201 hai; koi staff ban kar maange tab bhi hargiz mat dena.",
            "Harbor Bank jaankari: Khate mein paise lene ke liye kabhi UPI PIN daalne ya collect prompt accept karne ki zaroorat nahi padti.",
            "Meridian Bank suraksha: Agar koi call kar ke kahe ki galat charge hatane ke liye mobile par aaya code batao to turant phone kaat dein.",
        ]),
        ("calibration", "hinglish", 0, "v5_cal_hi_benign_b", [
            "Crestline Bank mahine aur taimahi khata report: October ka poora e-statement https://reports.crestline.example/oct-pdf par dekha ja sakta hai.",
            "Evergreen Pay grahak ledger aur PDF passbook https://docs.evergreenpay.example/ledger mein upload ho chuki hai.",
            "Solstice Bank niyam: Netbanking aur card OTP hamesha niji rakhein; bank adhikari kabhi calls ya links par KYC details nahi poochte.",
            "Pinnacle Pay note: Branch par jama ki gayi aapki KYC file poori tarah update aur approved ho chuki hai.",
        ]),
        ("calibration", "english", 1, "v5_cal_en_scam_a", [
            "Hey sis, stuck at interstate barrier after phone bricked and borrowing security guard's hotspot. Transfer 4,400 rs to this UPI ID immediately, cannot answer voice here.",
            "Ma my SIM network crashed in storm and I need Rs. 6,700 wired right away to book emergency train quota; don't call back as battery sits at 2 percent.",
            "Horizon Mart refund cleared smoothly: Authorize incoming collect notification of INR 1,750 immediately in payment app to settle refund cash into A/c XX9920.",
            "Harbor risk notice: Validate KYC credentials tonight or corporate netbanking and card usage will deactivate automatically before 6 AM.",
        ]),
        ("calibration", "english", 1, "v5_cal_en_scam_b", [
            "Global marketplace part-time opening! No interview required, daily payout INR 3,200 through Telegram—sign up now and submit Rs. 850 starter kit fee.",
            "Merchant dispute team: Rs. 2,899 annual club charge is posting tonight. Read aloud the 6-digit security passcode sent to SMS so we cancel the fee.",
            "Policy states guard your codes from callers. Even so, reply with your 6-digit confirmation OTP immediately to recover your pending cashback.",
        ]),
        ("calibration", "hinglish", 1, "v5_cal_hi_scam_a", [
            "Bhaiya highway par gaadi ruk gayi, mera phone toot gaya aur anjaan passenger ka hotspot use kar raha hoon. Abhi turant 4600 rs is UPI par bhejo, yahan call mat lagana.",
            "Maa baarish mein mera purana phone band ho gaya, bus seat book karne ke liye turant 5800 rs transfer kar do; battery 1% par hai isliye voice call mat karna.",
            "Oakwood store wapsi rashi INR 1,550 bhejne ke liye payment prompt par authorize aur PIN pushti karein.",
        ]),
        ("calibration", "hinglish", 1, "v5_cal_hi_scam_b", [
            "Meridian bank grahak notice: Jaldi KYC details update karein warna aaj raat netbanking aur card services band kar di jayengi.",
            "Ecommerce part-time job offer! Ghar baithe Telegram par roz 3300 rs kamayein; id activate karne ke liye abhi Rs. 900 starter kit deposit karein.",
            "Billing desk se bol raha hoon, card par 3,799 ka galat charge aa gaya; cancel karwane ke liye phone par aaya one-time code abhi padh kar sunao.",
            "Kisi ko secret code mat batana, lekin atki hui refund rashi release karne ke liye aaya hua OTP abhi text mein bhej do.",
        ]),

        # ==================== VALIDATION ADDITIONS (completely separate families & wording) ====================
        ("validation", "english", 0, "v5_val_en_benign_a", [
            "Meridian Trust alert: 491082 is your verification OTP for POS purchase INR 1,920.00 at Metro Grid. Do not expose this passcode to bank callers or outsiders.",
            "Oakwood Credit statement alert: Quarterly fee brochure and passbook PDF hosted at https://vault.oakwoodcredit.example/quarterly-pack.",
            "Solstice UPI settlement: Received transfer of INR 1,380.00 into savings account ending 9042. Ref 882716253410.",
            "Crestline Pay Awareness: Con artists trap accounts using collect prompts posing as prizes or refunds. Remember you never input a UPI PIN to receive cash.",
        ]),
        ("validation", "english", 0, "v5_val_en_benign_b", [
            "Harbor cyber note: Avoid short URLs claiming sudden PAN lock or KYC deadline; confirm updates only inside your bank's installed mobile portal.",
            "Banyan Coop reminder: Protect against remote-support scams—never install screen-mirroring tools or pass SMS login tokens to callers offering fee reversals.",
            "Evergreen Pay: You temporarily paused ATM withdrawals and locked debit card XX3810 inside settings toggles. Unpause anytime through your official banking app.",
            "Reserved counter slot #22 at Horizon Bank MG counter for your routine scheduled annual KYC file check on 08-Dec-26.",
        ]),
        ("validation", "english", 0, "v5_val_en_benign_c", [
            "Sunrise Branch confirmation: Your identity KYC verification at Oakwood Jayanagar branch finished cleanly with zero follow-up tasks pending.",
            "Pinnacle Pay auto-reversal: INR 2,410.00 from an incomplete UPI transfer settled automatically back into your linked savings balance.",
        ]),
        ("validation", "hinglish", 0, "v5_val_hi_benign_a", [
            "Aapke Crestline Pay profile verify karne ke liye 704928 one-time code bheja gaya hai; yeh kisi ko bol kar ya text par hargiz na dein.",
            "Harbor Credit web login ka OTP 385910 hai; koi helpline se bol raha hoon keh kar maange tab bhi mat batana.",
            "Banyan Pay jaankari: Paise prapt karne ke liye kabhi UPI PIN daalne ya collect prompt approve karne ki zaroorat nahi padti.",
            "Oakwood Bank jaagrukta: Agar koi bole ki kati rakam lautane ke liye phone par aaya code padh kar sunao to turant call disconnect karein.",
        ]),
        ("validation", "hinglish", 0, "v5_val_hi_benign_b", [
            "Solstice Bank mahina report: October 2026 ke liye aapka monthly e-statement https://reports.solsticebank.example/oct-pdf par dekha ja sakta hai.",
            "Meridian Pay aur savings khate ka pichla ledger PDF https://files.meridianpay.example/monthly-ledger mein uplabdh hai.",
            "Evergreen Trust niyam: Aapka login password aur 6-digit OTP hamesha gupt rakhein; bank kabhi calls ya links par KYC details nahi maangta.",
            "Cedar Fin branch note: Counter par jama aapki KYC file poori tarah update aur approved ho gayi hai.",
        ]),
        ("validation", "hinglish", 0, "v5_val_hi_benign_c", [
            "Online ticket payment aur bill settlement Rs. 1,120.00 ke liye OTP 449102 screen par daalein. Yeh code kisi ko forward mat karo.",
            "Aapne app aur portal ke zariye apna debit card aur ATM spend temporarily band kar diya hai; jab chahein wapas chalu karein.",
        ]),
        ("validation", "english", 1, "v5_val_en_scam_a", [
            "Hey brother, stranded near state toll booth after phone went black and using stranger's hotspot. Wire 3,900 rs via UPI right away, cannot talk in weak signal.",
            "Mom my regular SIM died at airport arrival and I need INR 7,100 transferred immediately for cab advance; don't ring back, phone battery is 2 percent.",
            "Meridian Mart refund cleared: Authorize the collect prompt of INR 1,620 right away inside your UPI portal to release refund cash into A/c XX4102.",
            "Solstice Bank compliance notice: Finish KYC re-update tonight or digital banking and debit access deactivate permanently tomorrow.",
        ]),
        ("validation", "english", 1, "v5_val_en_scam_b", [
            "Global retail part-time work hiring! Zero experience needed, daily wage INR 3,600 via Telegram—register immediately and transfer Rs. 980 starter kit charge.",
            "Card settlement team: Duplicate health debit Rs. 4,599 hits tonight. Dictate the 6-digit SMS security passcode aloud on call right now to halt debit.",
            "Advisories say never disclose OTPs. However, reply immediately with your verification digits to unlock your overdue reward payout.",
        ]),
        ("validation", "hinglish", 1, "v5_val_hi_scam_a", [
            "Papa highway toll par fasa hoon, mera phone dead ho gaya aur anjaan bande ka wifi hotspot le kar bhej raha hoon. Turant 4300 rs is UPI par wire karein, abhi call nahi ho payegi.",
            "Didi baarish mein meri primary SIM band ho gayi aur turant 6400 rs chahiye hostel slip ke liye; phone 1 percent par hai call mat lagana.",
            "Crestline Mart return settle hua hai: Account mein Rs. 1,480 refund deposit ke liye payment app mein collect notification turant authorize karo.",
        ]),
        ("validation", "hinglish", 1, "v5_val_hi_scam_b", [
            "Oakwood portal emergency chetavani: Aaj raat se pehle apni identity KYC verify karwayein warna netbanking band hogi.",
            "Online ecommerce part-time job bharti! Telegram par roz 3400 rupaye payout milega—aaj register karein aur Rs. 950 starter kit charge bhej dein.",
            "Support team se bol raha hoon, card par 3,299 ka extra charge kat raha hai; reverse ke liye aaya verification code turant padh kar sunao.",
            "Password kisi se share mat karo, par ruka hua subsidy claim credit karwane ke liye SMS par aaya code abhi bhej do.",
        ]),
    ]

    rows = []
    idx = 1
    for split, lang, label, family, texts in specs:
        for text in texts:
            rows.append({
                "id": f"v5d{idx:03d}",
                "split": split,
                "label": label,
                "language": lang,
                "family": family,
                "source": "synthetic_v5_dev",
                "text": text,
            })
            idx += 1
    return rows


def build_v5_holdout() -> list[dict]:
    """Build strictly fresh unseen 240 labeled (120 EN, 120 HI) + 24 ambiguous holdout messages.

    Uses 100% fresh fictional entities (Narmada Bank, Vindhya Trust, Satpura Pay, Coromandel Card,
    Yamuna Mart, Tapi Express, Cauvery Power, Mahanadi Water, Sahyadri Rail, Chinar Telecom,
    Brahmaputra Fin, Aravalli Hospital) completely absent from V1-V5 dev and V2-V4 holdouts.
    """
    specs = [
        # ==================== ENGLISH BENIGN (60 = 10 categories x 6) ====================
        ("english", 0, "otp_delivery", "v5h_en_otp", "ctrl5_otp_1", [
            "629104 is your Narmada Bank mobile login OTP. Never expose this code to callers or outsiders. Valid for 8 mins.",
            "Vindhya Trust alert: 840219 is your verification OTP for card spend INR 1,590.00 at Yamuna Mart. Do not share this token with bank callers or strangers.",
            "Use OTP 318472 to register your Coromandel Card inside the Satpura Pay wallet. Official executives never request this token.",
            "Your Satpura Pay temporary sign-in passcode is 502849 (expires in 5 minutes). Keep confidential at all times.",
            "Narmada Bank verification: Enter passcode 741903 inside your own mobile app to confirm recurring biller mandate.",
            "593810 is the OTP for your Cauvery Power electricity bill of Rs. 920.00 on Vindhya Card XX3104. Ignore any caller demanding it.",
        ]),
        ("english", 0, "fraud_awareness", "v5h_en_awareness", None, [
            "Narmada Bank Security Note: Con artists send alarming account-lock warnings and spoofed KYC pages. Our team never requests OTPs, MPINs, passwords, or UPI PINs.",
            "Public cyber bulletin from Vindhya Trust: Tricksters imitate helpline extensions alleging expired PAN or frozen cards. Never reveal CVV or ATM PINs.",
            "Satpura Pay Awareness: Swindlers deceive users via collect notifications masked as refunds or lottery wins. Remember you never input a UPI PIN to receive money.",
            "Safety advisory from Coromandel Card: Ignore texts pressing instant card verification over web links. Support staff never ask readers to dictate codes aloud.",
            "Citizen cyber note: Do not tap short URLs requiring emergency PAN or KYC validation; review account alerts exclusively inside your installed banking app.",
            "Narmada Bank reminder: Guard against screen-share fraud—never download remote-view utilities or pass SMS codes to callers promising fee refunds.",
        ]),
        ("english", 0, "debit_credit_receipt", "v5h_en_tx_receipt", None, [
            "Narmada Bank: A/c XX5291 credited with INR 22,400.00 on 20-Nov-26 via NEFT Ref NM8831042. Avl Bal INR 71,340.25.",
            "Vindhya Trust alert: INR 1,780.00 debited from A/c XX8140 on 20-Nov-26 at Yamuna Mart POS. Call 1800-555-0811 only if unauthorized.",
            "Coromandel Card XX6420 spent Rs. 2,950.00 at Tapi Express Booking on 19-Nov-26. Available credit balance is Rs. 1,18,400.00.",
            "Salary credit: Savings account ending 5291 at Narmada Bank received INR 48,500.00 via IMPS Ref 772190483211 on 19-Nov-26.",
            "Debit alert: Rs. 710.00 paid towards Sahyadri Rail fare via Vindhya debit card XX4022 on 19-Nov-26.",
            "Quarterly interest payout: INR 518.40 savings interest credited into Brahmaputra Fin A/c XX9182 on 18-Nov-26.",
        ]),
        ("english", 0, "failed_payment_reversal", "v5h_en_reversal", "ctrl5_refund_1", [
            "Narmada Bank settlement: Failed transaction of INR 1,490.00 at Yamuna Mart has reversed and credited cleanly back into A/c XX5291.",
            "Vindhya Trust auto-refund: Rs. 960.00 from an uncompleted Sahyadri Rail ticket attempt already settled into your savings balance. No PIN or code needed.",
            "Satpura Pay reversal: INR 2,340.00 from a declined UPI transfer returned automatically to your linked bank balance.",
            "Yamuna Mart refund update: INR 680.00 for returned household order credited cleanly into your source account ending 8140.",
            "Tapi Express settlement: Rs. 1,820.00 from your cancelled parcel order has posted back into Narmada A/c XX5291.",
            "Coromandel Card reversal confirmation: Duplicate POS swipe of INR 3,150.00 dropped off automatically without calling support.",
        ]),
        ("english", 0, "user_card_block", "v5h_en_user_block", "ctrl5_block_1", [
            "Narmada Bank update: Confirmation that you permanently blocked Coromandel Card XX6420 inside the official mobile application. Dial 1800-555-0811 if unintended.",
            "Vindhya Trust: As initiated by your mobile login, ATM card XX8140 has been deactivated immediately. Order reissue inside Card Controls if needed.",
            "Satpura Card lock: You paused international tap usage and locked debit card XX4022 temporarily in app settings. Toggle anytime inside the official portal.",
            "Brahmaputra Fin notice: Lost card XX9182 has been frozen per your request on helpline 1800-555-0811; replacement dispatch takes 4 working days.",
            "Coromandel Card record: Your manual in-app freeze submission for swipe card XX3104 succeeded cleanly with zero extra action.",
            "Vindhya Bank status: We recorded your self-requested debit disablement on card ending 4022; bank staff never call asking for PIN to restore access.",
        ]),
        ("english", 0, "branch_kyc_appointment", "v5h_en_branch_kyc", None, [
            "Narmada Bank desk notice: Confirmation for your routine KYC update appointment scheduled at Anna Nagar branch on 04-Dec-26 at 10:30 AM.",
            "Vindhya Trust: Your periodic Know Your Customer inspection at Civil Mall branch counter is confirmed for 06-Dec-26 at 11:45 AM; bring original photo ID.",
            "Branch confirmation: Your identity KYC documentation at Narmada Bank Park Road branch completed verification cleanly with zero tasks pending.",
            "Coromandel desk status: Thank you for visiting Rajajinagar branch; your KYC file was checked and marked current.",
            "Counter booking: Brahmaputra Fin assigned slot #19 at Alkapuri branch for your scheduled annual KYC desk review on 09-Dec-26.",
            "Satpura Trust record update: Branch-submitted periodic KYC review has finished processing cleanly.",
        ]),
        ("english", 0, "statement_notification", "v5h_en_statement", None, [
            "Narmada Bank statement alert: October 2026 e-statement for A/c XX5291 is ready at https://docs.narmadabank.example/statements/oct26.",
            "Vindhya Trust passbook desk: Download your quarterly checking summary online at https://portal.vindhyatrust.example/passbook.",
            "Coromandel Card monthly invoice: Cycle statement for card XX6420 posted safely at https://billing.coromandelcard.example/invoice.",
            "Brahmaputra Fin document note: Quarterly fee breakdown and interest PDF uploaded to https://archive.brahmaputra.example/fees.",
            "Chinar Telecom e-bill: Postpaid statement #CT77190 for Rs. 699.00 available at https://bills.chinartelecom.example/pdf.",
            "Satpura savings update: Your half-yearly TDS tax statement can be viewed at https://tax.satpurapay.example/tds-q2.",
        ]),
        ("english", 0, "upi_notification", "v5h_en_upi", None, [
            "Satpura UPI alert: Paid Rs. 540.00 from Narmada A/c XX5291 to Aravalli Medical Pharmacy. UPI Ref 662819045312.",
            "Via Vindhya UPI rail handle: INR 1,280.00 settled into customer account ending 8140 on 20-Nov-26 (UTR 491028374615).",
            "Transferred INR 915.00 cleanly via Satpura Pay to Mahanadi Fruit Mart on 20-Nov-26. Ref #550192837461.",
            "Narmada UPI receipt: Received Rs. 2,100.00 into A/c XX5291 from R. Kulkarni. Check live balance inside official mobile portal.",
            "Utility UPI confirmation: INR 1,450.00 remitted successfully to Cauvery Power Board. Txn Ref 719283746501.",
            "Satpura auto-pay: Recurring subscription Rs. 399.00 cleared to Chinar Telecom from Vindhya savings A/c XX8140.",
        ]),
        ("english", 0, "balance_notification", "v5h_en_balance", None, [
            "Narmada Bank info: Cleared available balance in savings A/c XX5291 on 20-Nov-26 EOD is INR 71,340.25.",
            "Vindhya Trust balance summary: Account XX8140 holds INR 29,615.80 clear funds as of 09:30 AM today.",
            "Coromandel Card update: Remaining credit headroom on XX6420 stands at INR 1,18,400.00 out of total INR 1,50,000.00.",
            "Brahmaputra Fin checking snapshot: Current balance stands at Rs. 14,980.00 with zero uncleared cheque holds.",
            "Satpura wallet statement: Total spendable balance is INR 4,210.00. Review complete ledger anytime inside app.",
            "Narmada OD facility balance: Utilized amount INR 0.00, available credit limit INR 50,000.00.",
        ]),
        ("english", 0, "delivery_utility_benign", "v5h_en_utility", None, [
            "Yamuna Mart dispatch: Order #YM88412 shipped via Tapi Express and reaches tomorrow before 6 PM. Track inside merchant orders tab.",
            "Cauvery Power confirmation: Payment INR 1,890.00 settled for Consumer #CP55102. Next meter billing falls on 20-Dec-26.",
            "Aravalli Hospital reception: Confirmed dental checkup slot at 11:30 AM Saturday with Dr. Nair; carry prior X-ray file.",
            "Mahanadi Water utility receipt: Monthly charge Rs. 420.00 received cleanly under Account MW30912. Zero outstanding dues.",
            "Sahyadri Rail notification: Coach B4 Berth 32 confirmed for Train 12640 departing Friday 07:15 AM from Central.",
            "Chinar Telecom alert: Monthly 50 GB mobile plan renewed cleanly for another 28 days on primary line.",
        ]),

        # ==================== ENGLISH SCAM (60 = 10 categories x 6) ====================
        ("english", 1, "account_block_threat", "v5h_en_block", "ctrl5_block_1", [
            "URGENT Narmada Bank notice: Your savings A/c will freeze tonight! Verify PAN immediately at https://bit.ly/narmada-unfreeze to retain access.",
            "Vindhya Trust alert: Debit card XX8140 is deactivated due to suspicious swipe. Log in via https://vindhya-unblock.example right now to prevent lockout.",
            "Coromandel Card security threat: Your credit line will suspend permanently in 2 hours unless you unlock at https://t.co/coromandel-lock.",
            "Brahmaputra Fin warning: Account XX9182 restricted! Reply urgently with debit card digits and CVV to prevent account shutdown.",
            "CRITICAL: Satpura Pay portal flagged unrecognized login—your netbanking deactivates tonight unless verified on https://tinyurl.com/satpura-sec.",
            "Narmada Bank emergency notice: Your ATM card is temporarily locked! Unblock immediately by sending PIN and birth year via SMS.",
        ]),
        ("english", 1, "otp_pin_solicitation", "v5h_en_otp", "ctrl5_otp_1", [
            "Narmada Bank Desk: Share your 6-digit OTP immediately so support can reverse an unauthorized debit of INR 5,400.00 on XX5291.",
            "Vindhya Card security team calling: Provide your ATM PIN and CVV right away to stop suspicious foreign charges.",
            "Coromandel Support: Text back your 4-digit MPIN alongside SMS verification passcode now to keep rewards active.",
            "Security reminder says guard codes, yet reply immediately with your SMS one-time password to release your blocked refund.",
            "Satpura Helpdesk: Forward the 6-digit security token delivered to your mobile immediately to authorize wallet limit upgrade.",
            "Always protect passwords from outsiders; however, send your 6-digit verification code right now to complete bonus reversal.",
        ]),
        ("english", 1, "fake_kyc_link", "v5h_en_kyc", None, [
            "Narmada customer warning: KYC validation overdue! Click https://bit.ly/narmada-kyc within 2 hours or mobile banking terminates automatically.",
            "Vindhya e-KYC alert: Update Aadhaar and PAN records at https://vindhya-ekyc-portal.example immediately to escape account freeze.",
            "Coromandel Credit compliance: Re-verify KYC details urgently at https://tinyurl.com/coromandel-pan else your card closes tonight.",
            "Brahmaputra KYC desk: Submit netbanking credentials and PAN verification promptly via https://brahma-verify.example to keep transactions enabled.",
            "Satpura Trust notice: Re-KYC verification failed; tap https://rb.gy/satpura-ekyc immediately so salary payouts do not bounce.",
            "Vindhya compliance emergency: Confirm KYC particulars urgently tonight or netbanking deactivates permanently at midnight.",
        ]),
        ("english", 1, "fake_refund", "v5h_en_refund", "ctrl5_refund_1", [
            "Yamuna Mart return settled cleanly: Authorize this collect notification of INR 1,490 right away inside your UPI portal to deposit refund cash into A/c XX5291.",
            "Tapi Express compensation Rs. 2,350 sanctioned for delayed delivery: Approve incoming payment collect popup immediately with UPI PIN to receive payout.",
            "Cauvery Power rebate INR 1,890 ready! Accept the collect request prompt inside Satpura Pay and confirm PIN to credit your account.",
            "Coromandel annual fee waiver Rs. 999 unlocked—tap Approve on our collect notification now so credit transfers back.",
            "Keep account codes secret with strangers; however, accept this Rs. 1,900 collect request immediately to claim your double-charge refund.",
            "Sahyadri Rail cancellation rebate INR 1,640 issued: Confirm the collect popup on mobile right away to pull funds into bank balance.",
        ]),
        ("english", 1, "read_aloud_otp", "v5h_en_read_aloud", None, [
            "Billing desk alert: Rs. 3,899 duplicate membership fee queued on Coromandel Card. Read out the 6-digit confirmation code aloud on call right now to void it.",
            "Narmada fraud control desk calling: We issued an abort passcode to block a rogue debit. Speak every digit of that security token aloud right now.",
            "Support audit desk: Read aloud the single-use verification code just sent to your inbox so we stop an erroneous INR 4,900 deduction.",
            "Merchant dispute team calling regarding Rs. 2,750 excess bill: Dictate the SMS authentication code aloud over phone immediately for reversal.",
            "Subscription cancellation unit: Your card gets billed INR 1,999 in 5 minutes—read out the confirmation code delivered to your phone aloud right now.",
            "Bank protection desk: Never disclose PINs carelessly, yet dictate the 6-digit reversal code aloud on this call immediately to freeze the thief's transfer.",
        ]),
        ("english", 1, "family_transfer_urgent", "v5h_en_family", None, [
            "Hey brother, stranded near highway toll gate after phone died and borrowing a stranger's wifi. Wire 3,500 rs to this UPI ID right now, signal too poor for voice calls.",
            "Ma my regular SIM stopped working in downpour and I need Rs. 8,200 sent right away to book bus berth; don't ring back, handset battery sits at 1 percent.",
            "Dad texting off a colleague's phone because my display went dead on campus. Transfer INR 6,100 urgently via Satpura UPI right now, mic is broken so don't call.",
            "Hey Auntie, lost my primary device in taxi and writing from driver's phone. Please transfer Rs. 4,900 immediately to this wallet handle, can't take voice calls inside clinic.",
            "Sis urgent—my SIM blocked outstation and I borrowed hostel friend's number. Send Rs. 5,400 right away to this QR handle, ring later not now.",
            "Mom messaging off neighbor's device after dropping mine in elevator shaft. Wire INR 7,600 urgently via UPI for pharmacy deposit, do not dial back.",
        ]),
        ("english", 1, "delivery_customs_scam", "v5h_en_delivery", None, [
            "Tapi Express Customs hold: International courier held at airport bay; deposit Rs. 650 clearance fee at https://bit.ly/tapi-duty today or package is forfeited.",
            "Yamuna Courier alert: Address unreadable on parcel #YN4401—update house pin and settle Rs. 45 re-dispatch charge on https://tapi-rebook.example immediately.",
            "Customs clearance urgent notice: Your parcel faces return today! Pay duty charge INR 890 via https://tinyurl.com/parcel-tax right away.",
            "Shipping desk alert: Warehouse storage charge Rs. 520 overdue on express docket; complete payment at https://rb.gy/ship-release before 6 PM.",
            "Final delivery call from Tapi Logistics: Verify delivery token and pay INR 295 reattempt charge at https://express-rebook.example now.",
            "Import fee warning: Courier parcel stopped for incomplete declaration—submit KYC and Rs. 780 duty on https://customs-verify.example urgently.",
        ]),
        ("english", 1, "prize_lottery_scam", "v5h_en_prize", None, [
            "CONGRATULATIONS! Your mobile digit won Narmada Bumper Lucky Draw INR 7,50,000! Claim immediately at https://bit.ly/narmada-jackpot.",
            "Satpura Festival Jackpot: Winner selected for Rs. 50,000 instant voucher + gold coin! Transfer Rs. 499 processing fee via https://satpura-win.example.",
            "Coromandel Rewards Bonus: Unclaimed cash prize Rs. 25,000 lapses tonight—tap https://tinyurl.com/coromandel-bonus and input card CVV.",
            "Chinar Telecom Anniversary Draw: You won a flagship phone + INR 1,00,000 cash! Pay shipping charge now on https://t.co/chinar-prize.",
            "Vindhya Mega Lottery notice: Rs. 2,50,000 award reserved under your SIM—share bank A/c details and Rs. 1,200 GST fee at https://vindhya-lotto.example.",
            "Special cashback jackpot Rs. 18,500 approved on Satpura Pay! Enter UPI PIN via https://rb.gy/win-claim before midnight.",
        ]),
        ("english", 1, "job_scam", "v5h_en_job", None, [
            "Remote digital storefront reviewer hiring! No prior resume required, Rs. 3,600 daily pay through Telegram desk—apply fast with Rs. 999 starter deposit.",
            "Remote product-rating job opening: Earn Rs. 2,400–4,800 per day liking store listings! Join Telegram desk immediately and send Rs. 750 slot deposit.",
            "Work-from-home data verification job hiring fast! Guaranteed Rs. 3,200 daily bank transfer; tap https://bit.ly/wfh-onboarding to purchase toolkit.",
            "URGENT part-time media promoter recruitment: Daily wage INR 4,100 straight from phone; message Telegram trainer and pay Rs. 899 ID fee.",
            "International travel brand hiring remote hotel reviewers! Daily salary Rs. 3,900; finish training deposit Rs. 1,100 via https://tinyurl.com/task-pay.",
            "Immediate online freelance job vacancy at Yamuna Partner Desk! Daily earnings Rs. 2,800; pay Rs. 650 registration charge to unlock assignments.",
        ]),
        ("english", 1, "utility_disconnect_scam", "v5h_en_utility_scam", None, [
            "URGENT Cauvery Power notice: Electricity supply will cut off tonight at 9:30 PM due to unverified last payment. Dial officer 9811002233 immediately.",
            "Mahanadi Water disconnection warning: Your home line faces shutoff today—update bill receipt on https://bit.ly/water-unblock right away.",
            "Cauvery Power Board Emergency: Meter deactivation queued for tonight; share UPI PIN or remote code with helpline 9700112244 immediately.",
            "DISCONNECT ALERT from Power Office: Last month invoice skipped ledger! Click https://tinyurl.com/cauvery-cutoff now to avoid meter pull.",
            "Chinar Telecom suspension warning: Mobile SIM gets permanently barred in 3 hours! Call verification executive 9822334455 urgently.",
            "Urgent municipal power disconnection SMS: Pay overdue INR 15 adjustment immediately on https://rb.gy/meter-stay or lose light tonight.",
        ]),

        # ==================== HINGLISH BENIGN (60 = 10 categories x 6) ====================
        ("hinglish", 0, "otp_delivery", "v5h_hi_otp", "ctrl5_hi_otp_1", [
            "Aapke Satpura Pay app verify karne ke liye 649201 one-time code bheja gaya hai; yeh kisi ko bol kar ya text par hargiz na dein.",
            "Vindhya Credit netbanking pravesh ka OTP 815492 hai; koi call kar ke officer bata kar maange to bhi mat batana.",
            "Coromandel Card POS kharid INR 1,620.00 ka OTP 309184 hai. Apna code aur login password kabhi share mat karein.",
            "Yamuna Mart checkout payment INR 950.00 ke liye OTP 724815 screen par daalein. Yeh gopniya code kisi ko forward mat karo.",
            "Narmada Bank NEFT payee jodne ke liye 518394 one-time password bheja gaya hai. Phone par kisi ko mat batayein.",
            "Cauvery Power bill jama karne ke liye Satpura verification code 992014 aaya hai; kisi caller ke maangne par na dein.",
        ]),
        ("hinglish", 0, "fraud_awareness", "v5h_hi_awareness", None, [
            "Satpura Pay chetavani: Bank khate mein rakam aane ke waqt kabhi UPI PIN bharna ya incoming request manzoor karna zaroori nahi hota.",
            "Narmada Bank savdhani: Koi bhi vyakti galat katoti wapas dilane ke bahane SMS par bheja code sunane ko kahe to turant phone rakh dein.",
            "Vindhya Trust niyam: Apna login secret aur 6-ankon ka token sada gupt rakhein; adhikari kabhi phone ya anjaan web address par KYC jankari nahi lete.",
            "Coromandel cyber suraksha: Anjaan chhote URL khol kar PAN ya KYC verify karne se bachein; asli update hamesha bank ki official app mein dikhta hai.",
            "Brahmaputra Fin soochna: Screen share karne wale apps kabhi download na karein aur fraudsters ko reward ya refund ke naam par code na batayein.",
            "Savdhani sandesh: Nakli account band hone ka message ya jhootha call aaye to vishwas na karein aur helpline par seedha check karein.",
        ]),
        ("hinglish", 0, "debit_credit_receipt", "v5h_hi_tx_receipt", None, [
            "Narmada Bank update: Khata XX5291 mein NEFT dwara Rs. 15,800.00 credit ho gaye hain. Uplabdh balance INR 68,420.00 hai.",
            "Vindhya Trust: Aapke card XX8140 se Yamuna Mart par Rs. 1,450.00 aur booking par Rs. 320.00 kharch hue. Balance app mein dekhein.",
            "Coromandel Card XX6420 se Tapi Express par INR 2,180.00 ka payment safal raha. Baki credit seema Rs. 1,18,400.00 hai.",
            "Brahmaputra savings khate mein Rs. 4,500.00 jama hue aur naye IMPS Ref 882104938271 ki pushti ho gayi hai.",
            "Aravalli Pharmacy par Vindhya debit card XX4022 se Rs. 675.00 debit kiye gaye; agar aapne kharch nahi kiya to bank helpline par call karein.",
            "Narmada savings khate XX5291 mein taimahi byaj ke Rs. 485.20 jama kar diye gaye hain.",
        ]),
        ("hinglish", 0, "failed_payment_reversal", "v5h_hi_reversal", "ctrl5_hi_refund_1", [
            "Satpura Pay auto-refund: Fail hui Rs. 1,240.00 ki payment wapas aapke linked Narmada khate mein credit ho gayi hai; koi approval nahi chahiye.",
            "Yamuna Mart radd order ke Rs. 890.00 aapke Vindhya bank account mein seedhe laut aaye hain, UPI PIN daalne ki zaroorat nahi.",
            "Sahyadri Rail booking fail hone se kata hua Rs. 1,750.00 wapas balance mein jama ho chuka hai; kisi link par click na karein.",
            "Coromandel POS double katoti ke Rs. 2,310.00 khud hi aapke card statement mein adjust aur credit kar diye gaye hain.",
            "Cauvery utility transaction radd hone par Rs. 1,180.00 wapas khata ending 5291 mein deposit ho gaye hain.",
            "Tapi Express par cancel kiye gaye ticket ka refund Rs. 1,560.00 aapke source khate mein aa chuka hai.",
        ]),
        ("hinglish", 0, "user_card_block", "v5h_hi_user_block", "ctrl5_hi_block_1", [
            "Narmada mobile banking se aapke dwara card XX6420 ko self-lock kar diya gaya hai; anjaan gatividhi lagne par 1800-555-0811 par soochna dein.",
            "Vindhya Trust notice: Aapke request par ATM card XX8140 ko permanently deactivate aur band kar diya gaya hai.",
            "Satpura Card jaankari: Mobile portal ke Card Control mein ja kar aapne khud swipe aur international card XX4022 freeze kiya hai.",
            "Card gum hone par aapke nirdesh par Brahmaputra debit card XX9182 lock kar diya gaya hai; naya card ghar pahunch jayega.",
            "Coromandel app confirmation: Aapne apna credit card XX3104 temporarily pause kiya hai aur jab chahein settings se on kar sakte hain.",
            "Aapke dwara banking login se debit card band karwane ki prakriya poori ho chuki hai; kisi executive ko OTP dene ki zaroorat nahi.",
        ]),
        ("hinglish", 0, "branch_kyc_appointment", "v5h_hi_branch_kyc", None, [
            "Vindhya Trust note: Branch par jama aapki KYC file poori tarah update aur approved ho gayi hai, aage koi karwai nahi bachi.",
            "Narmada Bank soochna: Anna Nagar branch par aapki routine KYC appointment 04-Dec ko subah 10:30 AM baje scheduled hai.",
            "Coromandel desk: Branch par aapne jo KYC dastawez aur identity proof diye the woh verify ho kar record mein current mark ho chuke hain.",
            "Brahmaputra Fin branch desk: Alkapuri branch mein annual KYC renewal ke liye aapka counter slot number 19 Monday ko book hua hai.",
            "Satpura Trust: Counter par jama ki gayi aapki KYC verification safaltapoorvak poora ho gayi hai, koi reply nahi bhejna hai.",
            "Narmada Bank appointment reminder: Alag counter visit ke liye kal dopahar Civil Mall branch mein original ID saath laayein.",
        ]),
        ("hinglish", 0, "statement_notification", "v5h_hi_statement", None, [
            "Narmada savings khate ka pichle maah ka PDF ledger https://docs.narmadabank.example/statement par check kiya ja sakta hai.",
            "Satpura Pay aapke pichle mahine ke sabhi transactions ki PDF report aur summary https://reports.satpurapay.example/ledger mein uplabdh hai.",
            "Vindhya Trust khata summary: Aapka taimahi passbook aur tax byaj statement https://portal.vindhyatrust.example/passbook par taiyar hai.",
            "Coromandel Card bill aur kharch statement PDF https://billing.coromandelcard.example/oct-pdf par upload kar diya gaya hai.",
            "Brahmaputra khata statement aur yearly TDS certificate https://archive.brahmaputra.example/tds par download ke liye uplabdh hai.",
            "Chinar Telecom postpaid mahina bill PDF https://bills.chinartelecom.example/monthly par check kar lein.",
        ]),
        ("hinglish", 0, "upi_notification", "v5h_hi_upi", None, [
            "Satpura UPI update: Aapne Yamuna Mart ko Rs. 620.00 bheje aur UPI Ref 441029384756 darj hua.",
            "Narmada Bank aur Satpura wallet se Rs. 1,450.00 Brahmaputra khate mein credit ho gaye hain. Khata ending 5291.",
            "Cauvery Power bijli aur utility bill ke Rs. 1,890.00 UPI Ref 991827364512 se safaltapoorvak jama ho chuke hain.",
            "Vindhya Pay dwara Aravalli Hospital pharmacy mein Rs. 780.00 ka payment poora raha. Naya balance app mein dekhein.",
            "Ramesh ji ko UPI se Rs. 950.00 bhejne par Narmada A/c XX5291 debit hua hai, ledger app par update ho gaya hai.",
            "Mahanadi Jal bill ke Rs. 420.00 Satpura UPI ke madhyam se jama kar diye gaye hain. Ref 661122334455.",
        ]),
        ("hinglish", 0, "balance_notification", "v5h_hi_balance", None, [
            "Narmada Bank savings A/c XX5291 mein aaj din ke ant par uplabdh balance INR 71,340.25 aur hold rashi shunya hai.",
            "Vindhya Trust khata XX8140 ka taja available balance Rs. 29,615.80 hai. Jankari ke liye official app check karein.",
            "Coromandel Card XX6420 par abhi Rs. 1,18,400.00 ki kharch seema baaki hai; agli due tareekh 05-Dec hai.",
            "Satpura Pay aur linked khate ka mila kar kul uplabdh balance INR 4,210.00 darj kiya gaya hai.",
            "Brahmaputra savings account balance report: Aapke khate mein Rs. 14,980.00 safe aur clear hain.",
            "Narmada FD aur savings khate ka kul jama balance aaj subah app ke ledger mein update ho gaya hai.",
        ]),
        ("hinglish", 0, "delivery_utility_benign", "v5h_hi_utility", None, [
            "Yamuna Mart order parcel Tapi Express se bhej diya gaya hai aur kal shaam tak ghar pahunchega. Status app mein dekhein.",
            "Cauvery bijli vibhag: Consumer #CP55102 par Rs. 1,890.00 aur meter shulk jama ho gaya hai. Agla bill agle mahine aayega.",
            "Aravalli Hospital reception: Shanivar subah 11:30 AM Dr. Nair ke paas aapka appointment confirm hai, purani report saath le aana.",
            "Mahanadi Jal bill Rs. 420.00 poori tarah jama ho gaya aur ab koi pichla bakaya nahi bacha hai.",
            "Sahyadri Rail jaankari: Friday subah 07:15 AM ki train mein aapki seat B4-32 confirm ho gayi hai. Shubh yatra!",
            "Chinar Telecom recharge notification: Aapka 50 GB data aur unlimited call pack agle 28 din ke liye chalu ho gaya hai.",
        ]),

        # ==================== HINGLISH SCAM (60 = 10 categories x 6) ====================
        ("hinglish", 1, "account_block_threat", "v5h_hi_block", "ctrl5_hi_block_1", [
            "Narmada Bank urgent warning: Aaj raat aapka savings khata band ho jayega! Turant https://bit.ly/narmada-block par KYC update karein.",
            "Vindhya ATM card XX8140 block ho raha hai—bachne ke liye abhi https://vindhya-unlock.example khol kar card details bharein.",
            "Coromandel Credit card 2 ghante mein deactivate ho jayega! Turant https://t.co/coro-kyc par ja kar MPIN aur OTP verify karein.",
            "SATPURA EMERGENCY: Aapka wallet freeze hone wala hai, turant https://tinyurl.com/satpura-unfreeze par login password daalein.",
            "Brahmaputra bank khata suraksha khatre mein hai; band hone se rokne ke liye abhi card number aur CVV message mein bhejein.",
            "Narmada netbanking tonight band ho rahi hai! Chalu rakhne ke liye customer helpline 9811223344 par turant ATM PIN batayein.",
        ]),
        ("hinglish", 1, "otp_pin_solicitation", "v5h_hi_otp", "ctrl5_hi_otp_1", [
            "Narmada helpdesk: Aapke khate se Rs. 4,900 katne wala hai, rokne ke liye SMS mein aaya 6-digit OTP turant bhej do.",
            "Vindhya card support: Apna ATM PIN aur CVV abhi share karo taaki aapke card par laga extra charge cancel ho sake.",
            "Coromandel billing executive bol raha hoon: Limit badhane ke liye phone par bheja gaya verification OTP aur DOB turant reply karein.",
            "Apna password surakshit rakhein, magar pending Rs. 2,500 bonus pane ke liye aaya hua 6-digit code abhi bhejo.",
            "Satpura Pay team: Wallet upgrade poora karne ke liye mobile inbox mein aaya OTP aur MPIN turant text kar dein.",
            "Bank rules kehte hain kisi anjaan ko code mat dein; phir bhi aapka ruka hua cashback bhejne ke liye abhi apna OTP batao.",
        ]),
        ("hinglish", 1, "fake_kyc_link", "v5h_hi_kyc", None, [
            "Vindhya khata suraksha sandesh: Samay se pehle online KYC dobara verify karo nahi to aaj madhyaratri ko mobile banking ruk jayegi.",
            "Narmada e-KYC zaroori soochna: Turant https://bit.ly/narmada-ekyc par PAN link karein nahi to khata hamesha ke liye freeze hoga.",
            "Coromandel PAN verification adhoori hai! https://tinyurl.com/coro-verify khol kar aaj hi details bharein warna card block hoga.",
            "Brahmaputra KYC desk: Aaj shaam 6 baje se pehle https://brahma-ekyc.example par login aur Aadhaar number submit karo warna paisa atak jayega.",
            "Satpura KYC alert: Aapka wallet verification fail ho gaya hai; abhi https://rb.gy/satpura-kyc par ja kar dobara chalu karein.",
            "Narmada Trust final reminder: Bina link ke emergency KYC aaj raat khatam ho rahi hai, turant netbanking aur card number SMS se bhej dein.",
        ]),
        ("hinglish", 1, "fake_refund", "v5h_hi_refund", "ctrl5_hi_refund_1", [
            "Yamuna Mart return ke Rs. 1,490 aapke account mein dalne ke liye mobile app ke andar aayi collect notification par turant approve aur PIN dabayein.",
            "Tapi Express delay ke Rs. 2,200 credit hone ke liye taiyar hain; Satpura app par aayi collect notification accept karo taaki paisa account mein aaye.",
            "Aapka double kata hua 1,850 rupaya refund ho raha hai! UPI collect prompt par approve daba kar PIN confirm karo.",
            "Aravalli clinic billing rebate Rs. 1,600 lene ke liye turant incoming collect notification authorize karein.",
            "Chinar telecom cashback Rs. 1,250 jama karwane ke liye screen par dikh rahi collect request abhi accept karein.",
            "Kisi anjaan ko code na dein, par atki hui Rs. 2,900 rashi khate mein paane ke liye aayi payment request par abhi approve dabao.",
        ]),
        ("hinglish", 1, "read_aloud_otp", "v5h_hi_read_aloud", None, [
            "Coromandel billing team se bol raha hoon, card par 3,999 ka galat renewal kat raha hai; reverse ke liye phone par aaya one-time code abhi padh kar sunao.",
            "Narmada fraud department: Aapke debit card par Rs. 4,800 ka foreign charge laga hai, rokne ke liye mobile par aaya 6-digit code turant bol kar batao.",
            "Charge wapas lene ke liye aapke number par jo verification code aaya hai woh bina ruke abhi padh kar bata do.",
            "Subscription team se call hai—aaj Rs. 2,499 katne wale hain; ise radd karwane ke liye SMS wala code abhi bol kar sunao.",
            "Aapke khate par galat bima fee Rs. 3,199 lag gayi hai, turant radd karne ke liye inbox mein bheja gaya security code dictate karo.",
            "Security rule bolta hai OTP mat do, lekin ruka hua payment wapas khate mein dalwane ke liye aaya code phone par abhi padh kar sunao.",
        ]),
        ("hinglish", 1, "family_transfer_urgent", "v5h_hi_family", None, [
            "Bhaiya toll barrier par phans gaya hoon, mera mobile dead ho gaya aur anjaan bande ka hotspot le kar bhej raha hoon. Turant 3900 rs is UPI par wire karein, call nahi lagegi.",
            "Maa baarish mein meri primary SIM aur screen kharab ho gayi; ticket book karne ke liye turant 7200 rs transfer kar do, battery 1% par hai abhi call mat karna.",
            "Papa main dost ke second phone se message bhej raha hoon kyunki mera phone station par chhoot gaya. Clinic deposit ke liye abhi 8500 rupaye send kar do, please ring mat lagana.",
            "Didi mera handset toot gaya hai aur mic bilkul band hai. Emergency dawai ke liye 4800 rs abhi is QR UPI par bhej dein, ghar aakar wapas karta hoon.",
            "Chacha wallet aur purana phone market mein ghum ho gaya, guard ke number se likh raha hoon. Jaldi 5600 rs is account par bhejo, hospital mein call receive nahi hogi.",
            "Mummy train nikalne wali hai aur mera phone hang ho gaya, saath wale ke number se msg kiya hai. Abhi 6100 rs is UPI ID par transfer karo.",
        ]),
        ("hinglish", 1, "delivery_customs_scam", "v5h_hi_delivery", None, [
            "Tapi Express customs notice: Aapka bahar se aaya parcel airport par atka hai; aaj hi Rs. 750 duty https://bit.ly/tapi-duty par jama karein.",
            "Yamuna delivery hold: Aapke ghar ka address adhoora hai—re-delivery ke liye https://tapi-track.example par ja kar Rs. 45 card se bharein.",
            "Express courier aakhri chetavani: Packet aaj wapas bheja ja raha hai! Turant https://tinyurl.com/parcel-clear par verify karein.",
            "Import duty Rs. 890 baaki hone se parcel ruka hai; abhi https://rb.gy/customs-pay par jama karo nahi to zapt ho jayega.",
            "Delivery boy number nahi lag raha, location update aur Rs. 200 slot charge ke liye https://yamuna-ship.example link kholo.",
            "International gift packet release karwane ke liye Rs. 999 clearance shulk abhi https://t.co/gift-customs par transfer karein.",
        ]),
        ("hinglish", 1, "prize_lottery_scam", "v5h_hi_prize", None, [
            "BADHAI HO! Aapke phone number ne Narmada Mega Lottery mein Rs. 5,00,000 jeeta hai! Claim ke liye abhi https://bit.ly/narmada-win kholein.",
            "Satpura Diwali bumper inaam Rs. 75,000 + laptop nikla hai! Delivery pane ke liye Rs. 499 fee https://satpura-draw.example par bhejo.",
            "Coromandel loyalty draw mein aapko Rs. 40,000 cash reward mila hai—claim ke liye https://tinyurl.com/coro-prize par card details daalein.",
            "Chinar Telecom lucky draw winner! Rs. 1,25,000 aur mobile jeetne par turant Rs. 999 GST charge https://t.co/chinar-inaam par bhejo.",
            "Vindhya Jackpot Rs. 3,00,000 aaj expire ho jayega; bank A/c aur PIN https://vindhya-reward.example par abhi verify karein.",
            "Festive spin bonus Rs. 20,000 aapke khate mein aane wala hai, receive karne ke liye https://rb.gy/cash-spin link par PIN daalo.",
        ]),
        ("hinglish", 1, "job_scam", "v5h_hi_job", None, [
            "Ghar baithe ecommerce part-time job vacancy! Telegram par roz 3500 rupaye payout milega—aaj register karein aur Rs. 999 starter kit charge jama karein.",
            "Online mobile task job offer: Bina kisi interview ke daily Rs. 2800 kamayein! Abhi Telegram join karein aur Rs. 750 training kit fee bhejo.",
            "Work from home product rating kaam ke liye turant bharti! Daily Rs. 3200 khate mein; shuru karne ke liye https://bit.ly/wfh-kit link se Rs. 850 jama karein.",
            "Part-time social media promoter bharti! Rozana income INR 4200 seedha phone se; Telegram trainer ko msg kar ke Rs. 950 registration bhejein.",
            "Yamuna Partner freelance job vacancy! Roz 2 ghante kaam kar ke Rs. 3000 payout; ID unlock karwane Rs. 699 security deposit turant transfer karo.",
            "Hotel review part-time work: Guarantee Rs. 3800 daily kamayi; abhi https://tinyurl.com/job-starter par Rs. 1,100 kit deposit bhejo.",
        ]),
        ("hinglish", 1, "utility_disconnect_scam", "v5h_hi_utility_scam", None, [
            "Cauvery Power urgent notice: Pichla bijli bill update na hone se aaj raat 9:30 PM par meter kaat diya jayega. Turant 9811220033 par officer se baat karein.",
            "Mahanadi Jal vibhag warning: Aapke ghar ka paani connection aaj band ho raha hai; turant https://bit.ly/jal-unblock par bill verify karein.",
            "Bijli meter disconnection alert! Chalu rakhne ke liye abhi https://tinyurl.com/power-stay par Rs. 25 adjustment card se bharein.",
            "Chinar Telecom emergency: 3 ghante mein aapka mobile number aur SIM hamesha ke liye band hoga! Turant 9700112255 par OTP de kar rokein.",
            "Electricity board final notice: Aaj raat light katne se bachne ke liye turant remote app install kar ke executive 9822001144 ko code batayein.",
            "Cauvery smart meter offline warning: Connection band hone se pehle https://rb.gy/meter-recheck par consumer details update karo.",
        ]),

        # ==================== AMBIGUOUS HOLDOUT (24 = 12 EN + 12 HI, label=None) ====================
        ("english", None, "ambiguous_callback", "v5h_en_ambig_cb", None, [
            "Hi, calling from a colleague's desk regarding Thursday's project handover notes; ping back when free.",
            "Please return my call on this alternate extension to confirm building parking slot allocation.",
            "Hello, this relates to the appliance service visit requested last week; give us a ring after 4 PM.",
            "Could you call me on this number once you finish reviewing the revised rent lease draft?",
        ]),
        ("english", None, "ambiguous_payment_reminder", "v5h_en_ambig_pay", None, [
            "Friendly note that Rs. 1,650 for this month's apartment elevator maintenance pool is due Saturday.",
            "Hey, Rs. 420 shared cab split from airport drop is still pending; settle whenever you open the app.",
            "Annual sports club membership fee of INR 500 can be cleared at the front desk this week.",
            "Lab stationery contribution Rs. 850 from semester batch students is due before Friday seminar.",
        ]),
        ("english", None, "ambiguous_sparse_link", "v5h_en_ambig_link", None, [
            "Uploaded this week's society committee minutes and gate roster at https://committee.example/minutes.",
            "Updated badminton court Saturday match brackets live on https://court-draw.example/saturday.",
            "Check revised workshop room map and speaker schedule on https://conf-notes.example/agenda.",
            "Apartment generator servicing timetable posted on https://block-notice.example/schedule.",
        ]),
        ("hinglish", None, "ambiguous_callback", "v5h_hi_ambig_cb", None, [
            "Bhaiya free ho kar is number par wapas call kar dena, Sunday function ke guest list par baat karni thi.",
            "Hello, aapke scooter servicing ke papers office mein pade hain; time milne par ring kar lena.",
            "Zaroori file discuss karni thi, meeting se nikal kar ek baar is phone par callback kar dijiye.",
            "Delivery gate par samaan rakha hai, receive karne ke liye guard bhai ko phone laga lena.",
        ]),
        ("hinglish", None, "ambiguous_payment_reminder", "v5h_hi_ambig_pay", None, [
            "Society pani tanki safai ke Rs. 350 is mahine ke end tak office room mein dene ka reminder hai.",
            "Kal shaam ke snacks aur coffee ka Rs. 320 hisaab baaki hai, free ho kar bhej dena.",
            "Library card renew karne ka Rs. 400 chulk agle Somwar tak counter par jama kar dein.",
            "Picnic bus booking advance Rs. 1,100 ka reminder—aaj raat tak final list lock karni hai.",
        ]),
        ("hinglish", None, "ambiguous_sparse_link", "v5h_hi_ambig_link", None, [
            "Cricket tournament ka naya Sunday schedule https://club-fixture.example/sunday par upload hua hai.",
            "Apartment lift maintenance time table https://block-notice.example/lift par dekh lein.",
            "Seminar ke updated slides aur reading material https://seminar-docs.example/notes par check kar sakte hain.",
            "Hostel mess ka agle hafte ka naya menu https://mess-menu.example/weekly par lag gaya hai.",
        ]),
    ]

    rows = []
    idx = 1
    for lang, label, category, family, pair_id, texts in specs:
        for text in texts:
            row = {
                "id": f"v5h{idx:03d}",
                "label": label,
                "language": lang,
                "category": category,
                "family": family,
                "source": "synthetic_v5_holdout",
                "text": text,
            }
            if pair_id is not None:
                row["pair_id"] = pair_id
            rows.append(row)
            idx += 1
    return rows


def main() -> None:
    v4_dev = read_jsonl(ROOT / "data/synthetic/v4_development.jsonl")
    v5_add = _build_v5_development_additions()
    v5_dev = v4_dev + v5_add
    v5_hold = build_v5_holdout()

    # Validate V5 development structure & zero internal leakage
    ids_dev = set()
    for r in v5_dev:
        assert r.get("split") in ("train", "calibration", "validation")
        assert r.get("label") in (0, 1)
        assert r["id"] not in ids_dev, f"Duplicate id {r['id']}"
        ids_dev.add(r["id"])
        r["text"] = normalize_sms(r["text"])
    check_leakage(v5_dev)

    # Validate V5 holdout structure & exact class/language balance
    ids_hold = set()
    for r in v5_hold:
        assert r.get("label") in (0, 1, None)
        assert r["id"] not in ids_hold, f"Duplicate holdout id {r['id']}"
        ids_hold.add(r["id"])
        r["text"] = normalize_sms(r["text"])

    assert sum(1 for r in v5_hold if r["label"] in (0, 1)) == 240
    assert sum(1 for r in v5_hold if r["label"] is None) == 24
    assert sum(1 for r in v5_hold if r["language"] == "english" and r["label"] == 0) == 60
    assert sum(1 for r in v5_hold if r["language"] == "english" and r["label"] == 1) == 60
    assert sum(1 for r in v5_hold if r["language"] == "hinglish" and r["label"] == 0) == 60
    assert sum(1 for r in v5_hold if r["language"] == "hinglish" and r["label"] == 1) == 60

    # Strict family separation across dev splits and V5 holdout
    dev_fams_by_split = {
        sp: {r["family"] for r in v5_dev if r["split"] == sp}
        for sp in ("train", "calibration", "validation")
    }
    hold_fams = {r["family"] for r in v5_hold}
    for i, a in enumerate(("train", "calibration", "validation")):
        assert not (dev_fams_by_split[a] & hold_fams), f"Family overlap {a} vs holdout"
        for b in ("train", "calibration", "validation")[i + 1:]:
            assert not (dev_fams_by_split[a] & dev_fams_by_split[b]), f"Family overlap {a} vs {b}"

    # Guarantee zero overlap against ALL prior holdouts, UCI processed splits, and reproduced strings
    external_rows = []
    for tag, rel in (
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

    # Entity firewall: ensure zero holdout brand tokens enter V5 dev additions and zero V4/dev brands enter V5 holdout
    v5_hold_exclusive_brands = (
        "narmada", "vindhya", "satpura", "coromandel", "yamuna mart", "tapi express",
        "cauvery", "mahanadi", "sahyadri", "chinar", "brahmaputra", "aravalli",
    )
    v4_hold_exclusive_brands = ("kaveri", "deccan", "nilgiri", "saffron", "malabar", "tamarind", "chambal", "konkan", "palash", "godavari")
    v5_dev_text_blob = " \n ".join(r["text"].lower() for r in v5_add)
    for b in v5_hold_exclusive_brands + v4_hold_exclusive_brands:
        assert b not in v5_dev_text_blob, f"Leaked holdout entity {b!r} in V5 dev additions!"

    v5_hold_text_blob = " \n ".join(r["text"].lower() for r in v5_hold)
    forbidden_in_v5_hold = (
        v4_hold_exclusive_brands
        + ("harbor bank", "solstice", "meridian", "evergreen", "crestline", "banyan coop", "oakwood", "cedar", "pinnacle", "sunrise mart", "horizon rail", "metro grid")
    )
    for b in forbidden_in_v5_hold:
        assert b not in v5_hold_text_blob, f"Leaked dev/v4 entity {b!r} in V5 holdout!"

    # Exact canonical overlap check
    dev_canon = {canonical(r["text"]): r for r in v5_dev}
    hold_canon = {canonical(r["text"]): r for r in v5_hold}
    ext_canon = {canonical(r["text"]): r for r in external_rows}
    assert not (set(dev_canon) & set(hold_canon)), "Exact canonical overlap V5 dev vs V5 holdout!"
    assert not (set(dev_canon) & set(ext_canon)), f"Exact canonical overlap V5 dev vs ext: {set(dev_canon) & set(ext_canon)}"
    assert not (set(hold_canon) & set(ext_canon)), f"Exact canonical overlap V5 hold vs ext: {set(hold_canon) & set(ext_canon)}"

    # Stricter near-duplicate audit (cosine >= 0.85) across V5 dev splits, V5 holdout, and external/repro sets
    tagged = (
        [{"id": r["id"], "partition": f"dev:{r['split']}", "text": r["text"]} for r in v5_dev]
        + [{"id": r["id"], "partition": "v5_hold", "text": r["text"]} for r in v5_hold]
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
        if len(parts_set) > 1 and any(item_id.startswith(("v5h", "v5d", "v4d", "v3d")) for item_id in ids):
            # Ignore purely prior V3/V4 internal matches with non-V5 partitions unless involving V5 items
            if any(item_id.startswith(("v5h", "v5d")) for item_id in ids):
                cross_hits.append(items)

    assert not cross_hits, f"V5 cross-partition near-duplicate collisions (>=0.85): {cross_hits}"

    dev_out = ROOT / "data/synthetic/v5_development.jsonl"
    hold_out = ROOT / "data/synthetic/v5_holdout.jsonl"
    write_jsonl(dev_out, v5_dev)
    write_jsonl(hold_out, v5_hold)

    summary = {
        "v5_development_sha256": digest(dev_out),
        "v5_holdout_sha256": digest(hold_out),
        "v5_dev_total": len(v5_dev),
        "v5_add_count": len(v5_add),
        "v5_dev_counts": {
            sp: {
                "total": sum(r["split"] == sp for r in v5_dev),
                "label_0": sum(r["split"] == sp and r["label"] == 0 for r in v5_dev),
                "label_1": sum(r["split"] == sp and r["label"] == 1 for r in v5_dev),
                "english": sum(r["split"] == sp and r["language"] == "english" for r in v5_dev),
                "hinglish": sum(r["split"] == sp and r["language"] == "hinglish" for r in v5_dev),
            }
            for sp in ("train", "calibration", "validation")
        },
        "v5_holdout_counts": {
            "total": len(v5_hold),
            "labeled": sum(r["label"] in (0, 1) for r in v5_hold),
            "ambiguous": sum(r["label"] is None for r in v5_hold),
            "english_0": sum(r["language"] == "english" and r["label"] == 0 for r in v5_hold),
            "english_1": sum(r["language"] == "english" and r["label"] == 1 for r in v5_hold),
            "hinglish_0": sum(r["language"] == "hinglish" and r["label"] == 0 for r in v5_hold),
            "hinglish_1": sum(r["language"] == "hinglish" and r["label"] == 1 for r in v5_hold),
        },
        "near_dup_cross_partition_085_v5_hits": len(cross_hits),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
