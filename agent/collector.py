import win32evtlog
import xml.etree.ElementTree as ET

def sysmon_event_stream():
    server = 'localhost'
    logtype = 'Microsoft-Windows-Sysmon/Operational'

    # Open the event log
    hand = win32evtlog.OpenEventLog(server, logtype)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            continue

        for ev_obj in events:
            try:
                # Convert the event to XML string
                xml_str = ev_obj.StringInserts[0] if ev_obj.StringInserts else ""
                # Parse with ElementTree (Sysmon logs are XML structured)
                # If xml_str is empty, skip
                yield {
                    "event_id": ev_obj.EventID,
                    "time": ev_obj.TimeGenerated,
                    "source": ev_obj.SourceName,
                    "computer": ev_obj.ComputerName,
                    "message": xml_str
                }
            except Exception as e:
                yield {"error": str(e)}
