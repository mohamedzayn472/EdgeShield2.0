"""Rebuild authored v2 development examples; never opens a holdout or original data.

Every family has six controlled variations. These are AI-assisted synthetic
fixtures, not independent observations or claims about actual messages.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "synthetic" / "v2_development.jsonl"
FAMILIES: list[dict] = []


def add(split: str, language: str, label: int, name: str, stem: str, details: str) -> None:
    language = "english" if language == "en" else language
    variants = details.split(" | ")
    if len(variants) != 6 or stem.count("{detail}") != 1:
        raise ValueError(f"Family {name} must have six variations and one detail slot")
    FAMILIES.append(dict(split=split, language=language, label=label,
                         family="v2_" + name, stem=stem, variants=variants))


# TRAIN: twelve families in each language/label cell. No family crosses a split.
add("train", "en", 0, "en_balance_receipt",
    "Cedar Bank account SIM1001: {detail} This is a transaction receipt.",
    "Your salary credit has posted | Interest for the quarter was credited | A cash deposit was recorded | Your cheque deposit has cleared | The scheduled savings transfer is complete | Your standing instruction was processed")
add("train", "en", 0, "en_card_record",
    "Pebble Cards purchase notice: {detail} Review purchases in the app you normally use.",
    "A bookstore payment was approved | Your grocery purchase was processed | The travel booking amount was debited | A cafe transaction settled today | The fuel purchase has been recorded | Your cinema booking payment succeeded")
add("train", "en", 0, "en_login_code",
    "Moss Bank: {detail} OTP 000000 expires in five minutes. Do not disclose it to anyone.",
    "You requested a sign-in code | Your registered device requested verification | A password reset was initiated in your app | This code confirms your own login attempt | Your app requested a second authentication step | Use this code only in the sign-in screen you opened")
add("train", "en", 0, "en_security_warning",
    "Juniper Bank security bulletin: {detail} Staff do not need your secret codes.",
    "Never send an OTP to somebody claiming to unblock your account | Do not share your PIN with a caller promising a refund | Refuse any request to reveal your card security code | Do not read a login password aloud over the phone | Never approve a payment because a stranger calls it a verification | Decline requests to install remote control software for banking")
add("train", "en", 0, "en_kyc_branch",
    "Willow Savings KYC notice: {detail} Bring documents to your usual branch; this SMS does not request them.",
    "Your periodic record review is due next month | The address verification appointment is available | Your identity document review is scheduled | The branch can explain the renewal process | A reminder for your planned record update | Your document validity review is approaching")
add("train", "en", 0, "en_upi_receipt",
    "Maple Payments UPI receipt: {detail} Reference DEMO100. No approval is needed for this completed transaction.",
    "Your grocery payment was successful | The electricity bill payment settled | Your rent transfer reached the recipient | A restaurant payment completed | Your mobile recharge was credited | The water bill payment has finished")
add("train", "en", 0, "en_collect_controls",
    "Birch Pay safety reminder: {detail} Review unfamiliar requests in your own payment app.",
    "Reject a UPI collect request you did not expect | Approving a collect request sends money from your account | Receiving money does not require entering your UPI PIN | A refund does not require you to authorize a debit | Do not approve a stranger's payment request to receive a reward | A caller cannot verify your identity by asking for your payment PIN")
add("train", "en", 0, "en_parcel_status",
    "Clover Parcel tracking update for order DEMO101: {detail}",
    "Your package left the warehouse this morning | The courier will attempt delivery tomorrow | Your delivery address correction was saved | Your parcel is ready at the pickup desk | The package was delivered to your chosen locker | Heavy rain has delayed the delivery route")
add("train", "en", 0, "en_interview_schedule",
    "Fern Labs recruitment: {detail} The interview is free and no payment or banking details are requested.",
    "Your technical interview is scheduled for Monday | Your portfolio review will take place remotely | Your application reached the interview stage | The hiring panel has moved your appointment to Thursday | Please bring a sample of your work to the meeting | Your campus placement interview slot is confirmed")
add("train", "en", 0, "en_refund_settled",
    "Acorn Store refund update: {detail} The amount returns to the original payment method automatically.",
    "Your cancelled book order has been refunded | The duplicate purchase charge was reversed | Your returned headphones passed inspection | The delivery fee adjustment was processed | Your unavailable grocery item was refunded | The returned jacket refund is complete")
add("train", "en", 0, "en_subscription_options",
    "Pine Music account reminder: {detail} Manage your preference in the application you already have.",
    "Your subscription renews next week | Your free listening period ends tomorrow | The family plan renewal date has changed | Your monthly receipt is available | Your cancellation takes effect after this billing period | The annual membership is due for renewal")
add("train", "en", 0, "en_everyday_plans",
    "{detail}",
    "I will meet you outside the library after class. Bring the notebook if you remember. | The badminton court booking is confirmed for Saturday afternoon. See you there. | Please collect your lunch box from the kitchen when you get home. | Our project meeting has moved to the second floor seminar room. | The community garden volunteers are gathering near the gate tomorrow. | Your borrowed novel is on my desk. You can pick it up after the lecture.")

add("train", "en", 1, "en_otp_support_theft",
    "Cedar Bank support says {detail} Send the OTP you just received to this chat so our agent can proceed.",
    "your account needs urgent unlocking | a failed login must be cancelled immediately | a new device must be removed from your account | a suspicious transfer is waiting to be stopped | your banking profile requires instant reactivation | your mobile banking access will expire today")
add("train", "en", 1, "en_refund_pin_theft",
    "Pebble refund desk: {detail} Reply with your full UPI PIN to release the money.",
    "You have a pending shopping refund | Your duplicate bill charge is ready to return | We found an excess delivery charge | Your cancelled ticket refund is waiting | An unclaimed merchant rebate is reserved | Your failed purchase has generated a reimbursement")
add("train", "en", 1, "en_receive_collect",
    "Moss rewards payment: {detail} Accept the UPI collect request and enter your PIN to receive these funds.",
    "Your cashback is ready | A loyalty credit is waiting | Your customer bonus has been approved | A festival reward is reserved for you | Your account promotion payout is available | A missed referral payment can now be claimed")
add("train", "en", 1, "en_advance_job_fee",
    "Juniper Careers: {detail} Send an advance hiring fee to the recruiter's personal payment account before we reveal the employer.",
    "You have been selected without an interview | A guaranteed remote job is reserved | Your instant appointment letter is waiting | A high salary home-based role is available | We can confirm your placement today | Your name is shortlisted for immediate joining")
add("train", "en", 1, "en_prize_fee",
    "Willow Prize Office: {detail} Transfer the release fee first; do not discuss this award with your bank.",
    "Your number won a cash lottery you never entered | A surprise jackpot has been allotted to you | You are the exclusive winner of an overseas draw | Your unrequested lucky reward is being held | A huge festival cash prize is in your name | Our secret selection chose you for a bonus award")
add("train", "en", 1, "en_block_credentials",
    "Maple Bank final warning: {detail} Enter your internet banking password and OTP at https://maple-review.example/restore now.",
    "Your account will be blocked within minutes | Your KYC is marked invalid today | Your balance access will be suspended | Your banking identity must be urgently repaired | Your debit services face immediate cancellation | Your account verification has expired")
add("train", "en", 1, "en_fake_court_fine",
    "Online Court Department: {detail} Pay the officer's private wallet immediately to avoid arrest; you must keep this secret.",
    "A sealed warrant was issued against you | Your identity appears in a confidential criminal case | An unpaid cyber penalty has been registered | Your name is linked to an illegal parcel | A digital detention order is awaiting clearance | Your account was named in a hidden investigation")
add("train", "en", 1, "en_delivery_card_capture",
    "Clover delivery clearance: {detail} Send your complete card number, expiry and security code in a reply to prevent cancellation.",
    "Your parcel has a tiny unpaid customs fee | A warehouse correction charge is pending | Your shipment needs an urgent address fee | A final delivery attempt requires a deposit | Your package release charge was not collected | An unexpected handling fee must be settled")
add("train", "en", 1, "en_remote_control",
    "Birch technical support: {detail} Install the remote-control app from https://birch-assist.example and share its access code while your banking app is open.",
    "We detected a banking error on your phone | Your payment app must be repaired remotely | A stuck refund needs a technician | Your bank screen has to be inspected now | A blocked transaction requires screen access | Your wallet needs an urgent security patch")
add("train", "en", 1, "en_safe_account_transfer",
    "Fern Bank fraud squad: {detail} Transfer your entire balance to our temporary personal account now; do not contact your branch.",
    "Your savings are under attack | An insider is trying to empty your account | Your deposit has been tagged for seizure | Hackers are waiting for your next login | A secret security operation must move your money | Your funds need emergency protection")
add("train", "en", 1, "en_loan_fee_release",
    "Acorn Instant Loans: {detail} Pay a processing advance to our agent's private wallet before any loan agreement or funds are provided.",
    "Your unsolicited loan is guaranteed | A large loan has been preapproved without checks | We reserved emergency credit in your name | Your instant business loan is sanctioned | Our no-document loan has been approved | An exclusive debt relief payout is ready")
add("train", "en", 1, "en_receive_qr_pin",
    "Pine buyer: {detail} Scan my QR and enter your payment PIN to collect the money; the debit warning is only verification.",
    "I will pay for your used bicycle now | Your secondhand desk payment is ready | I am sending the advance for your camera | Your old phone sale amount is waiting | I want to transfer money for the furniture | The payment for your listed monitor can be received now")

add("train", "hinglish", 0, "hi_bank_credit_notice",
    "Gulmohar Bank soochna: {detail} Yeh sirf receipt hai, jawab dena zaroori nahi.",
    "aapki salary jama ho gayi hai | bachat khate ka byaaj credit hua hai | cheque ki rakam account mein aa gayi hai | pension ki kisht jama ho chuki hai | cash deposit ki entry poori hui hai | fixed deposit ka maturity amount mil gaya hai")
add("train", "hinglish", 0, "hi_otp_notification",
    "Palash Bank: {detail} OTP 000000 sirf aapki kholi hui app mein daalein. Kisi ko code mat batana.",
    "aapne login code manga tha | naye login ke liye verification aaya hai | password badalne ki request mili hai | aapke registered device ne sign in shuru kiya | app mein authentication ka agla step hai | aapki shuru ki hui session verification hai")
add("train", "hinglish", 0, "hi_pin_awareness",
    "Neem Pay suraksha sandesh: {detail} PIN hamesha gupt rakhein.",
    "paise receive karne ke liye UPI PIN nahi lagta | refund dene wala aapse secret code nahi maangta | kisi caller ko OTP batana mana hai | anjaan collect request approve mat karo | reward ke badle payment authorise na karein | support ke naam par screen access mat dein")
add("train", "hinglish", 0, "hi_kyc_offline_reminder",
    "Amaltas Bank KYC yaad dilata hai: {detail} Apni jaani hui branch mein original kagaz dikhayein; SMS par kuch na bhejein.",
    "record review agle mahine due hai | address update ki appointment mil sakti hai | identity document ki validity check honi hai | branch ne aapka review slot rakha hai | periodic details update ka samay aa gaya hai | aapke document renewal ka reminder hai")
add("train", "hinglish", 0, "hi_upi_complete",
    "Kesar Payments: {detail} UPI transaction complete hai, dobara PIN daalne ki zaroorat nahi.",
    "kirane ki payment safal hui | bijli ka bill bhar diya gaya | kiraye ki rakam pahunch gayi | mobile recharge ho gaya | paani ka bill jama ho chuka | canteen ki payment mil gayi")
add("train", "hinglish", 0, "hi_delivery_status",
    "Titli Courier order DEMO202: {detail}",
    "aapka parcel kal dopahar pahunchega | packet sorting centre se nikal gaya hai | aaj barish ke kaaran delivery late hogi | aapka pickup counter par packet taiyar hai | parcel ghar ke chune hue locker mein rakh diya hai | aapki requested delivery date badal di gayi hai")
add("train", "hinglish", 0, "hi_campus_hiring",
    "Jugnu Labs placement update: {detail} Interview ya naukri ke liye koi fees nahi li jaati.",
    "aapka technical round somvaar ko hai | apna project portfolio meeting mein laayein | hiring panel ne samay badal kar teen baje kiya | campus interview ka kamra ab seminar hall hai | aapka application review poora hua | chune gaye candidates ka discussion kal hoga")
add("train", "hinglish", 0, "hi_purchase_reversal",
    "Champa Shop: {detail} Refund usi payment method par apne aap aayega.",
    "cancelled order ka paisa wapas process hua | duplicate charge reverse kar diya gaya | lautaye hue kapde ka refund manzoor hua | stock na hone par kitab ka paisa lauta diya | delivery adjustment ki rakam wapas bheji gayi | broken item ki return checking poori hui")
add("train", "hinglish", 0, "hi_atm_notice",
    "Kadamb Bank ATM entry: {detail} Details apne usual statement mein dekh sakte hain.",
    "aapki cash withdrawal record ho gayi | machine ne transaction cancel kiya aur debit reverse hua | cash deposit accept ho gaya | ATM receipt ki copy app mein mil jayegi | aapka daily withdrawal limit update save hua | ATM PIN change ki aapki request complete hui")
add("train", "hinglish", 0, "hi_bill_notice",
    "Aangan Utilities: {detail} Bhugtan ke liye apna pehle se istemal kiya hua portal kholein.",
    "is mahine ka bill tayyar hai | aapki meter reading darj ho gayi | bill ki due date agle hafte hai | pichhli payment ki receipt mil gayi | aapka paper bill band karne ka request save hua | billing address ka correction poora hua")
add("train", "hinglish", 0, "hi_card_controls",
    "Parijat Cards update: {detail} Yeh aapki app mein ki hui setting ka confirmation hai.",
    "online spending band kar di gayi hai | aapne card temporarily freeze kiya hai | international usage limit badal di gayi hai | contactless payment disable ho gayi hai | aapka naya spending limit save ho gaya | merchant alert preference update ho gayi hai")
add("train", "hinglish", 0, "hi_daily_plans",
    "{detail}",
    "Kal library ke bahar milte hain, assignment ki copy saath lana. | Ghar aate hue doodh le aana, main chai bana raha hoon. | Cricket practice ka time shaam paanch baje kar diya hai. | Aaj class online hogi, teacher ne group mein bataya hai. | Tumhari kitab mere bag mein hai, kal college mein de dunga. | Lunch canteen mein karenge, lecture ke baad seedha wahin aana.")

add("train", "hinglish", 1, "hi_support_otp_capture",
    "Gulmohar Bank agent: {detail} Abhi mila OTP isi chat mein bhejo, warna kaam ruk jayega.",
    "aapka account turant unlock karna hai | galat login cancel karna zaroori hai | naya device hatana padega | atka transfer rokna hai | banking profile dobara chalu karni hai | aapki mobile service aaj expire hogi")
add("train", "hinglish", 1, "hi_refund_secret_pin",
    "Palash refund team: {detail} Paisa release karne ke liye apna poora UPI PIN reply mein batao.",
    "aapka shopping refund taiyar hai | ticket cancellation ka paisa atka hai | delivery ka extra charge lautana hai | duplicate bill ka refund mila hai | referral reward wapas dena hai | merchant reimbursement approve hua hai")
add("train", "hinglish", 1, "hi_collect_receive_trick",
    "Neem bonus desk: {detail} Paise receive karne ke liye collect request approve karo aur PIN daalo.",
    "aapka cashback aa gaya | reward amount taiyar hai | customer bonus milna hai | festival gift cash mein milega | referral ka paisa pending hai | loyalty payment release hogi")
add("train", "hinglish", 1, "hi_job_advance",
    "Amaltas Jobs: {detail} Company ka naam batane se pehle recruiter ke personal wallet par registration fee bhejo.",
    "bina interview aapki naukri pakki hai | ghar baithe guaranteed salary milegi | turant joining letter taiyar hai | aapko private hiring mein chun liya | vacancy sirf aaj ke liye reserve hai | direct appointment approve ho gayi")
add("train", "hinglish", 1, "hi_lottery_release",
    "Kesar Lucky Draw: {detail} Pehle release charge bhejo aur bank ko is prize ke baare mein mat batana.",
    "bina entry aapka number jeet gaya | aapke naam bada lottery cash nikla | secret draw mein jackpot mila | surprise inaam sirf aapke liye hai | festival reward ka winner aap hain | foreign lottery ne aapko select kiya")
add("train", "hinglish", 1, "hi_kyc_password_link",
    "Titli Bank final KYC: {detail} Password aur OTP https://titli-verify.example/fix par turant daalo.",
    "account das minute mein band hoga | identity review fail ho gaya | balance access suspend hone wala hai | debit service rok di jayegi | verification aaj expire ho rahi hai | aapki banking profile block list mein hai")
add("train", "hinglish", 1, "hi_police_wallet_fine",
    "Cyber Adhikari: {detail} Giraftari rokne ke liye mere personal wallet par paisa bhejo, kisi ko mat batao.",
    "aapke naam gupt warrant nikla hai | aapki ID illegal parcel mein mili | account criminal case mein aaya | digital detention ka order taiyar hai | secret penalty register hui hai | aapka naam confidential inquiry mein hai")
add("train", "hinglish", 1, "hi_parcel_cvv",
    "Jugnu Parcel clearance: {detail} Card number, expiry aur CVV isi message ke jawab mein bhejo.",
    "packet par chhota customs charge baki hai | address correction ki fee atki hai | aakhri delivery attempt ka deposit chahiye | warehouse release payment nahi mili | handling charge turant jama karna hai | shipment cancellation rokna zaroori hai")
add("train", "hinglish", 1, "hi_screen_share_bank",
    "Champa technical team: {detail} https://champa-help.example se remote app lagao aur bank kholkar screen control code do.",
    "aapke phone mein banking error hai | payment app repair karni padegi | refund ke liye technician access chahiye | wallet ka security patch lagana hai | atki transaction screen par check hogi | account setting remotely theek karni hai")
add("train", "hinglish", 1, "hi_safe_wallet_transfer",
    "Kadamb Bank protection squad: {detail} Poora balance hamare personal safety account mein bhejo; branch se baat mat karo.",
    "aapke paise hacker nikalne wala hai | insider ne savings target ki hai | account seize hone ka khatra hai | funds ko secret operation mein bachana hai | aapka deposit turant shift karna padega | banking access par attack chal raha hai")
add("train", "hinglish", 1, "hi_loan_private_fee",
    "Aangan Loan Express: {detail} Agreement se pehle agent ke private UPI par advance processing fee bhejna zaroori hai.",
    "bina documents loan pakka hai | bada credit bina checking approve hua | emergency paisa aapke naam reserve hai | business loan turant mil jayega | debt relief amount taiyar hai | exclusive personal loan sanction hua")
add("train", "hinglish", 1, "hi_qr_sale_payment",
    "Parijat buyer: {detail} Rakam lene ke liye mera QR scan karke PIN daalo; debit warning ko ignore karo.",
    "aapki purani cycle ka paisa bhej raha hoon | used laptop ki payment taiyar hai | camera ki advance rakam deni hai | furniture ka full amount mil jayega | monitor ka sale payment aa raha hai | purane phone ke paise abhi receive karo")

# CALIBRATION: new families; no tuning examples from validation or a holdout.
add("calibration", "en", 0, "en_passkey_registered",
    "Harbor Account security receipt: {detail} If this was not you, open your existing account settings to review access.",
    "Your laptop passkey was registered | You removed an old authentication device | Your recovery method update was saved | A security key was added from your signed-in session | Your trusted browser list was changed | The passkey you selected has been revoked")
add("calibration", "en", 0, "en_failed_transfer_reversal",
    "Meadow Bank transfer status: {detail} Any temporary debit is reversed automatically; nobody needs your PIN.",
    "The recipient bank could not accept your transfer | Your transaction timed out before settlement | The beneficiary limit prevented completion | A network interruption stopped this transfer | The payment request expired without settlement | The receiving account rejected the credit")
add("calibration", "en", 1, "en_voicemail_login_capture",
    "Hearth Voicemail alert: {detail} To listen, enter your email password and recovery code at https://hearth-voice.example/unlock.",
    "An urgent legal recording is waiting | Your boss left a confidential voice note | A bank representative recorded a warning | A private delivery instruction was saved | A government officer sent an audio notice | Your account auditor left an emergency message")
add("calibration", "en", 1, "en_marketplace_release_deposit",
    "Brook Market escrow agent: {detail} Transfer a refundable verification deposit to my personal account before I release the buyer's funds.",
    "Your advertised table has been sold | A buyer paid for your used guitar | Your camera sale payment is locked | The bicycle buyer completed checkout | Your listed chair has a confirmed purchaser | The tablet sale proceeds are awaiting clearance")
add("calibration", "hinglish", 0, "hi_train_ticket_update",
    "Koyal Travel booking DEMO303: {detail} Apni booking details pehle se install app mein dekh lein.",
    "aapki seat confirm ho gayi hai | platform information update hui hai | train aadha ghanta late chal rahi hai | aapka boarding point correction save hua | ticket cancellation ka receipt tayyar hai | coach position ab available hai")
add("calibration", "hinglish", 0, "hi_bank_complaint_receipt",
    "Tesu Bank complaint DEMO304: {detail} Complaint team kabhi OTP ya password nahi maangegi.",
    "aapki shikayat register kar li gayi hai | branch ne aapke case ko review ke liye bheja hai | disputed charge par investigation shuru hui hai | aapke diye kagaz receive ho gaye hain | case update aapki banking app mein hai | aapka requested callback slot save ho gaya hai")
add("calibration", "hinglish", 1, "hi_power_cut_remote_fee",
    "Koyal Bijli officer: {detail} Supply bachane ke liye personal wallet par reconnection fee bhejo aur remote screen access do.",
    "aaj raat turant connection katega | meter record mein secret default mila | payment database ne aapko blacklist kiya | ghar ki supply final disconnection mein hai | purana bill achanak invalid ho gaya | emergency cutoff order aa chuka hai")
add("calibration", "hinglish", 1, "hi_pension_reactivate_secrets",
    "Tesu Pension Cell: {detail} Apna ATM PIN aur bank OTP is number ke reply mein bhejo tabhi pension khulegi.",
    "aapki pension verification fail hui | agle mahine ki kisht rok di gayi | life certificate achanak cancel hua | pension account inactive mark hua | beneficiary record delete hone wala hai | aapka arrears payment block hua hai")

# VALIDATION: sixteen further families. This is development data, not a fresh test.
add("validation", "en", 0, "en_kyc_completed_app",
    "Orchid Bank records update: {detail} Your KYC review is complete. No documents or payment are requested in this message.",
    "The address you submitted in our app was accepted | Your branch-verified identity record was renewed | Your scheduled document review has finished | The correction you requested has been applied | Your in-person verification has been recorded | The record update you authorized is now reflected")
add("validation", "en", 0, "en_installment_receipt",
    "Lark Finance installment statement: {detail} View the loan schedule through your usual signed-in account.",
    "This month's repayment was received | Your scheduled debit cleared successfully | The final installment closed your balance | The extra repayment reduced your principal | Your payment holiday request was recorded | The corrected interest entry appears on your statement")
add("validation", "en", 0, "en_employment_warning",
    "Ash Studio hiring notice: {detail} Submit applications only through the careers section you normally access.",
    "We never ask applicants to pay a recruitment deposit | Ignore anyone selling our interview slots | Do not transfer money to a person offering our job letters | Our recruiters do not collect card numbers | We do not sell guaranteed placement packages | No recruiter needs your bank login or OTP")
add("validation", "en", 0, "en_delivery_code_boundary",
    "Lotus Dispatch: {detail} Share only the delivery code with the courier after checking your package; never share banking OTPs.",
    "Your pre-paid parcel is at your door | Your ordered appliance is ready for handover | The courier has brought your booked package | Your replacement item has arrived | Your scheduled doorstep delivery is here | The parcel you expected is available for receipt")
add("validation", "en", 1, "en_credit_limit_cvv",
    "Orchid card upgrade desk: {detail} Reply with your card number, CVV and the bank OTP so we can activate it on your behalf.",
    "A secret credit limit increase is approved | Your premium card is waiting for activation | A lifetime fee waiver is reserved | Your spending limit can be doubled today | An exclusive card upgrade was selected for you | Your emergency credit extension is ready")
add("validation", "en", 1, "en_school_grant_release",
    "Lark Education Grant: {detail} First pay the release tax to our coordinator's private wallet; do not ask the school about this confidential award.",
    "Your child received an unrequested cash scholarship | A surprise tuition grant is in your name | A donor selected your family for a large award | Your student bonus has been approved without application | A special exam reward is waiting | Your education subsidy was secretly allotted")
add("validation", "en", 1, "en_tax_remote_access",
    "Ash Revenue Recovery: {detail} Install our remote-control tool at https://ash-tax.example/session and keep your bank open while the officer takes control.",
    "Your tax refund needs a screen inspection | Your return has a hidden compliance error | An urgent audit must examine your banking screen | A tax penalty can be cancelled remotely | Your refund account must be checked live | An officer must repair your refund destination")
add("validation", "en", 1, "en_prize_autopay_mandate",
    "Lotus Cash Awards: {detail} Approve this recurring debit mandate and enter your UPI PIN to receive the prize; ignore the subscription notice.",
    "Your festival reward is ready for collection | A lucky cash bonus has been assigned | Your customer contest payout is waiting | A surprise loyalty prize was released | Your promotion jackpot is confirmed | Your selected-member cash gift is available")
add("validation", "hinglish", 0, "hi_clinic_schedule",
    "Rangoli Clinic appointment: {detail} Yeh booking update hai, is SMS mein payment nahi maangi gayi.",
    "aapki doctor meeting kal subah hai | lab sample ka time dus baje rakha hai | doctor ki deri se slot aadha ghanta aage hua | aapka follow-up appointment confirm hai | reception par booking code DEMO404 dikhana hai | aapki consultation reschedule kar di gayi hai")
add("validation", "hinglish", 0, "hi_collect_request_declined",
    "Suraj Pay activity: {detail} Koi paisa debit nahi hua; anjaan collect request accept karna zaroori nahi.",
    "aapne payment request reject kar di | collect request ka samay khatam ho gaya | aapki decline choice save ho gayi | pending debit request cancel ho gayi | merchant ki expired request hata di gayi | unknown sender ki request aapne block kar di")
add("validation", "hinglish", 0, "hi_bill_autopay_settings",
    "Saheli Services mandate update: {detail} Yeh aapne khud app mein kiya tha; details apni settings mein dekhein.",
    "aapka monthly bill autopay band ho gaya | recurring payment limit kam kar di gayi | agle mahine ka automatic debit pause hua | utility mandate ki expiry update hui | aapka purana subscription debit revoke hua | selected bill ke liye reminder-only mode lag gaya")
add("validation", "hinglish", 0, "hi_login_review_warning",
    "Nandini Account alert: {detail} Agar yeh aap nahi the to khud apni usual app kholkar access check karein; kisi ko password na dein.",
    "naye browser se login dekha gaya | aapki recovery setting badli gayi | ek purana device remove hua | password reset request aayi | nayi security key add hui | trusted session list update hui")
add("validation", "hinglish", 1, "hi_parcel_digital_arrest",
    "Rangoli investigation officer: {detail} Digital arrest hatane ke liye security bond mere private account mein bhejo, lawyer se baat mat karo.",
    "aapke naam ka parcel illegal maal mein pakda gaya | courier package mein aapki ID mili | shipment ke naam par case khul gaya | aapka address secret smuggling file mein hai | warehouse se aapke naam suspicious packet nikla | parcel record ne aapko accused banaya hai")
add("validation", "hinglish", 1, "hi_guaranteed_investment_deposit",
    "Suraj Profit Club: {detail} Bina risk guaranteed double return ke liye paisa admin ke personal wallet mein bhejo; regulator ko batana mana hai.",
    "aaj ka secret investment slot khula hai | aapko exclusive trading group ne select kiya | instant profit plan sirf abhi available hai | special member bonus activate ho sakta hai | daily fixed gain ka private offer hai | aapke liye confidential growth package rakha hai")
add("validation", "hinglish", 1, "hi_scholarship_otp_capture",
    "Saheli Scholarship desk: {detail} Bank se aaya OTP aur login password hamein bhejo, hum aapke behalf par grant receive karenge.",
    "aapki student grant approve hui | fees reimbursement taiyar hai | merit cash award release hona hai | education bonus aapke naam aaya | special tuition aid ka payment atka hai | campus support fund aapko mila hai")
add("validation", "hinglish", 1, "hi_charity_pin_request",
    "Nandini Relief volunteer: {detail} Donation verify karne ke liye apna ATM PIN aur card CVV chat mein de dein; receipt baad mein milegi.",
    "aapke naam emergency pledge darj hai | flood relief contribution confirm karna hai | health camp support ki entry pending hai | food drive ke donor record ko check karna hai | winter aid promise ka approval chahiye | school relief fund ka commitment verify hoga")


def build_records() -> list[dict]:
    records: list[dict] = []
    seen_names: set[str] = set()
    seen_texts: set[str] = set()
    for family in FAMILIES:
        name = family["family"]
        if name in seen_names:
            raise ValueError("Duplicate family")
        seen_names.add(name)
        for i, detail in enumerate(family["variants"], 1):
            text = family["stem"].format(detail=detail)
            canonical = re.sub(r"\s+", " ", text).strip().casefold()
            if canonical in seen_texts:
                raise ValueError("Duplicate authored text")
            seen_texts.add(canonical)
            if not text or len(text) > 4096:
                raise ValueError("Invalid text length")
            records.append({"id": f"{name}_{i:02d}", "text": text,
                            "label": family["label"], "language": family["language"],
                            "family": name, "split": family["split"],
                            "source": "synthetic_ai_assisted"})
    counts = Counter((r["split"], r["language"], r["label"]) for r in records)
    expected = {"train": 72, "calibration": 12, "validation": 24}
    for split, count in expected.items():
        for language in ("english", "hinglish"):
            for label in (0, 1):
                if counts[split, language, label] != count:
                    raise ValueError("Unexpected group balance")
    if len(records) != 432 or len(seen_names) != 72:
        raise ValueError("Unexpected corpus size")
    return records


def main() -> None:
    records = build_records()
    payload = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in records)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(payload, encoding="utf-8", newline="\n")
    print(json.dumps({"path": str(OUTPUT.relative_to(ROOT)), "records": len(records),
                      "families": len(FAMILIES), "sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
                      "splits": dict(Counter(row["split"] for row in records)),
                      "source": "synthetic_ai_assisted", "holdout_accessed": False}, indent=2))


if __name__ == "__main__":
    main()
