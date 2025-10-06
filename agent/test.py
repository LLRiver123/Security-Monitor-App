import win32evtlog
import xml.etree.ElementTree as ET

channel = "Microsoft-Windows-Sysmon/Operational"
query = "*"

hand = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, query)

ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}  # namespace

total = 0
while True:
    events = win32evtlog.EvtNext(hand, 5)
    if not events:
        break
    for ev in events:
        xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
        root = ET.fromstring(xml)

        eid_node = root.find("./ev:System/ev:EventID", ns)
        ts_node = root.find("./ev:System/ev:TimeCreated", ns)

        eid = eid_node.text if eid_node is not None else "N/A"
        ts = ts_node.attrib.get("SystemTime") if ts_node is not None else "N/A"

        data = {}
        for d in root.findall(".//ev:EventData/ev:Data", ns):
            name = d.attrib.get("Name")
            data[name] = d.text

        print(f"EventID={eid} Time={ts} Image={data.get('Image')} User={data.get('User')} "
              f"SrcIP={data.get('SourceIp')} DstIP={data.get('DestinationIp')} DstPort={data.get('DestinationPort')}")
        total += 1

print("Total Sysmon events:", total)


