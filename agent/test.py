import win32evtlog

server = 'localhost'
logtype = "Microsoft-Windows-Sysmon/Operational"

# Open event log
hand = win32evtlog.OpenEventLog(server, logtype)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = 0

while True:
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    if not events:
        break
    for ev in events:
        print("Event ID:", ev.EventID, "Source:", ev.SourceName)
        total += 1

print("Total events read:", total)
