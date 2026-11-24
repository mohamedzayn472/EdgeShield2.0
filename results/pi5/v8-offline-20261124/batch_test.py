import subprocess
import json
import time

tests = [
    ("Bank OTP scam", "Your bank account will be blocked today. Share your OTP immediately."),
    ("Delivery notification", "Your order has been shipped. Track your delivery using tracking number ABC123."),
    ("Meeting reminder", "Good morning! The meeting is scheduled for 10 AM tomorrow. Bring your notes."),
    ("Suspicious link", "Your account is suspended. Verify immediately at http://secure-bank-login.example/verify."),
    ("OTP sharing", "Your verification code is 482913. Share this code with our support agent."),
    ("Bank transaction", "INR 450.00 has been debited from your account ending 1234. Available balance INR 12500."),
    ("Lottery scam", "Congratulations! You won 10 lakh rupees. Pay a processing fee to claim your prize."),
    ("Password reset", "We received a request to reset your password. If this wasn't you, contact our official support."),
    ("Urgent payment scam", "Pay immediately or your electricity connection will be disconnected today."),
    ("Family message", "Hi, I will reach home by 7 PM. Please keep dinner ready.")
]

results = []

for name, message in tests:
    process = subprocess.run(
        [".venv/bin/python", "-m", "edgeshield.cli", "--stdin", "--json"],
        input=message + "\n",
        capture_output=True,
        text=True
    )

    detection = None

    for line in process.stdout.splitlines():
        try:
            event = json.loads(line)
            if event.get("event") == "detection":
                detection = event
                break
        except json.JSONDecodeError:
            pass

    if detection:
        evidence = detection.get("evidence", {})
        results.append({
            "test": name,
            "classification": evidence.get("band"),
            "score": evidence.get("score"),
            "indicators": evidence.get("indicators"),
            "latency_ms": detection.get("detector_ms")
        })
    else:
        results.append({
            "test": name,
            "error": process.stderr.strip() or process.stdout.strip()
        })

print("\n========== EDGESHIELD V8 BATCH RESULTS ==========\n")

for i, result in enumerate(results, 1):
    print(json.dumps({"test_number": i, **result}))

with open("batch_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nResults saved to batch_results.json")
