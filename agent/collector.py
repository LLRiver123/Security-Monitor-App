import time
import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime

def sysmon_event_stream(batch_size=100, poll_delay=0.1):
    """
    Yield normalized Sysmon events as dicts:
      {
        "event_id": int,
        "time": "YYYY-MM-DDTHH:MM:SSZ",
        "source": str,
        "computer": str,
        "xml": "<event>...</event>",
        "data": { "Image": "...", "ParentImage": "...", "CommandLine": "...", ... }
      }
    Uses EvtQuery / EvtNext / EvtRender for better XML extraction.
    """
    channel = "Microsoft-Windows-Sysmon/Operational"
    query = "*"
    # EvtQueryReverseDirection is available in pywin32/Win32 API
    try:
        handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, query)
    except Exception as e:
        yield {"error": f"EvtQuery failed: {e}"}
        return

    ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

    while True:
        try:
            events = win32evtlog.EvtNext(handle, batch_size)
            if not events:
                time.sleep(poll_delay)
                continue

            for ev in events:
                try:
                    xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml)

                    # Basic fields
                    eid_node = root.find("./ev:System/ev:EventID", ns)
                    ts_node = root.find("./ev:System/ev:TimeCreated", ns)
                    comp_node = root.find("./ev:Computer", ns)
                    source_node = root.find("./ev:System/ev:Provider", ns)

                    event_id = int(eid_node.text) if eid_node is not None and eid_node.text else None
                    ts = ts_node.attrib.get("SystemTime") if ts_node is not None else None
                    # Normalize time to ISO (leave as-is if missing)
                    time_iso = None
                    if ts:
                        try:
                            # Example timestamp: 2021-09-01T12:34:56.123456Z
                            time_iso = datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
                        except Exception:
                            time_iso = ts

                    data = {}
                    for d in root.findall(".//ev:EventData/ev:Data", ns):
                        name = d.attrib.get("Name")
                        data[name] = d.text

                    yield {
                        "event_id": event_id,
                        "time": time_iso,
                        "source": source_node.attrib.get("Name") if source_node is not None else None,
                        "computer": comp_node.text if comp_node is not None else None,
                        "xml": xml,
                        "data": data,
                    }

                except Exception as e:
                    yield {"error": f"event parse error: {e}"}

        except KeyboardInterrupt:
            break
        except Exception as e:
            # transient query/read error, yield and back off
            yield {"error": f"EvtNext error: {e}"}
            time.sleep(1.0)
