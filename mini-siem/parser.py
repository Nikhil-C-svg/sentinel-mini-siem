"""Parse ISO-timestamped and traditional OpenSSH authentication logs."""
import re
from datetime import datetime, timezone
from ipaddress import ip_address

HEADER = re.compile(r"^(?P<stamp>\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<body>.*)$")
LOGIN = re.compile(r"^(?P<result>Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)(?: port \d+)?")

def parse_logs(text, year=2026, offset="+00:00"):
    events, rejected = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            match = HEADER.match(raw)
            if not match:
                raise ValueError("Unsupported log header")
            data = match.groupdict()
            login = LOGIN.match(data["body"])
            if not login:
                raise ValueError("Not a supported SSH login event")
            stamp = data["stamp"]
            if re.match(r"^[A-Z][a-z]{2} ", stamp):
                dt = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S")
                tz = datetime.fromisoformat("2000-01-01T00:00:00" + offset).tzinfo
                if tz is None:
                    raise ValueError("Timezone offset required")
                dt = dt.replace(tzinfo=tz)
            else:
                dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError("ISO timestamp requires timezone")
            item = login.groupdict()
            address = str(ip_address(item["ip"]))
            events.append(dict(timestamp=dt.astimezone(timezone.utc).isoformat(),
                hostname=data["host"], username=item["user"], source_ip=address,
                event_type="login_failed" if item["result"] == "Failed" else "login_success",
                raw_line=raw, line_number=number))
        except (ValueError, OverflowError) as exc:
            rejected.append(dict(line_number=number, reason=str(exc), raw_line=raw))
    return events, rejected
