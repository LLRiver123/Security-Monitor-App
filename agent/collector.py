import time
import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime

def sysmon_event_stream(batch_size=5, poll_delay=1.0):
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

                    # Normalize common fields into predictable keys and formats
                    norm = {}
                    # Keep original data dict for reference
                    norm.update(data)

                    # Normalize image paths and parent image
                    image = (data.get("Image") or "")
                    parent = (data.get("ParentImage") or "")
                    norm["Image"] = image
                    norm["ParentImage"] = parent
                    norm["ImageLower"] = image.lower() if image else ""
                    norm["ParentImageLower"] = parent.lower() if parent else ""

                    # Command line and hashes
                    cmd = (data.get("CommandLine") or "")
                    norm["CommandLine"] = cmd
                    norm["Hashes"] = data.get("Hashes") or ""

                    # Network fields (if present)
                    for net_field in ("SourceIp", "DestinationIp", "DestinationPort", "SourcePort"):
                        if net_field in data:
                            norm[net_field] = data.get(net_field)

                    # User field
                    if "User" in data:
                        norm["User"] = data.get("User")

                    yield {
                        "event_id": event_id,
                        "time": time_iso,
                        "source": source_node.attrib.get("Name") if source_node is not None else None,
                        "computer": comp_node.text if comp_node is not None else None,
                        "xml": xml,
                        "data": norm,
                    }

                except Exception as e:
                    yield {"error": f"event parse error: {e}"}

        except KeyboardInterrupt:
            break
        except Exception as e:
            # transient query/read error, yield and back off
            yield {"error": f"EvtNext error: {e}"}
            time.sleep(1.0)
