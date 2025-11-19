import time
import win32evtlog
import win32api
import xml.etree.ElementTree as ET
from datetime import datetime
import logging

logger = logging.getLogger('agent.collector')

# collector.py (Phiên bản Reverse Polling an toàn)

BOOKMARK_FILE = "sysmon_bookmark.xml"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
EVENT_LOG_QUERY = "*"


# --- CÁC HÀM HỖ TRỢ BOOKMARK AN TOÀN ---

def sysmon_event_stream():
    """
    Stream Sysmon events from the Windows Event Log using safe bookmarking.
    
    Yields:
        dict: Parsed Sysmon event in normalized format.
    """
    handle = None
    bookmark = None

    # Thử tải bookmark từ file nếu có
    try:
        with open(BOOKMARK_FILE, "r", encoding="utf-8") as f:
            bookmark_xml = f.read()
            bookmark = win32evtlog.EvtCreateBookmark(bookmark_xml)
            logger.info("Loaded bookmark from file.")
    except FileNotFoundError:
        logger.info("No existing bookmark file found; starting fresh.")
    except Exception as e:
        logger.error(f"Failed to load bookmark: {e}")

    try:
        # Tạo truy vấn sự kiện với bookmark nếu có
        handle = win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            win32evtlog.EvtQueryChannelPath,
            EVENT_LOG_QUERY,
            bookmark
        )
        logger.info("EvtQuery started for Sysmon events.")
    except Exception as e:
        logger.error(f"Failed to execute EvtQuery: {e}")
        yield {"error": f"EvtQuery failed: {e}"}
        return

    try:
        while True:
            # Lấy các sự kiện tiếp theo
            events = win32evtlog.EvtNext(handle, 100, 1000)
            
            if not events:
                time.sleep(1)  # Chờ trước khi kiểm tra lại
                continue
            
            for ev in events:
                # Xử lý sự kiện và Yield
                xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                parsed_event = _parse_event_xml(xml)
                
                if "error" not in parsed_event:
                    yield parsed_event
                
                # Cập nhật bookmark sau mỗi sự kiện thành công
                try:
                    new_bookmark = win32evtlog.EvtCreateBookmarkFromEvent(ev)
                    bookmark_xml = win32evtlog.EvtRender(new_bookmark, win32evtlog.EvtRenderBookmark)
                    with open(BOOKMARK_FILE, "w", encoding="utf-8") as f:
                        f.write(bookmark_xml)
                    logger.debug("Updated bookmark after processing event.")
                except Exception as e:
                    logger.error(f"Failed to update bookmark: {e}")
                    
    except Exception as e:
        logger.error(f"Error during event stream: {e}")
        yield {"error": f"Stream error: {e}"}

def _parse_event_xml(xml_string):
    """
    Parse Sysmon event XML into normalized dictionary format.
    
    Returns:
        dict: Normalized event with keys: event_id, time, source, computer, xml, data
    """
    # Namespace cần thiết để phân tích các thẻ Windows Event Log
    ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}
    
    try:
        root = ET.fromstring(xml_string)
        
        # 1. Trích xuất các trường Hệ thống (System fields)
        system = root.find("./ev:System", ns)
        if system is None:
            return {"error": "Missing System element in event"}
            
        eid_node = system.find("./ev:EventID", ns)
        ts_node = system.find("./ev:TimeCreated", ns)
        comp_node = root.find("./ev:System/ev:Computer", ns)
        source_node = system.find("./ev:Provider", ns)
        
        # Parse Event ID và Timestamp
        event_id = int(eid_node.text) if eid_node is not None and eid_node.text else None
        ts = ts_node.attrib.get("SystemTime") if ts_node is not None else None
        
        time_iso = None
        if ts:
            try:
                # Chuẩn hóa thời gian về ISO 8601
                time_iso = datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                ).isoformat()
            except Exception:
                time_iso = ts

        # 2. Trích xuất Dữ liệu Sự kiện (EventData fields)
        data = {}
        event_data = root.find(".//ev:EventData", ns)
        if event_data is not None:
            for data_node in event_data.findall("./ev:Data", ns):
                name = data_node.attrib.get("Name")
                if name:
                    data[name] = data_node.text if data_node.text else ""

        # 3. Trả về Dictionary Chuẩn hóa
        return {
            "event_id": event_id,
            "time": time_iso,
            "source": source_node.attrib.get("Name") if source_node is not None else None,
            "computer": comp_node.text if comp_node is not None else None,
            "xml": xml_string,
            "data": data,
        }
            
    except ET.ParseError as e:
        return {"error": f"XML parse error: {e}"}
    except Exception as e:
        return {"error": f"Event parsing error: {e}"}

def sysmon_event_stream_reverse(max_events=1000):
    """
    Retrieves the latest N events using reverse query, then stops.
    Used for UI display/refresh only.
    """
    handle = None
    
    try:
        # 💡 Dùng EvtQueryReverseDirection để đọc từ MỚI nhất về CŨ nhất
        handle = win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            win32evtlog.EvtQueryReverseDirection, 
            EVENT_LOG_QUERY,
            None
        )
        logger.info(f"Reverse EvtQuery started to fetch last {max_events} events.")
    except Exception as e:
        logger.error(f"Failed to execute Reverse EvtQuery: {e}")
        yield {"error": f"EvtQuery failed: {e}"}
        return

    fetched_count = 0
    
    try:
        while fetched_count < max_events:
            # Lấy các sự kiện tiếp theo
            events = win32evtlog.EvtNext(handle, min(100, max_events - fetched_count), 1000)
            
            if not events:
                break # Đã đọc hết log
                
            for ev in events:
                # 💡 Xử lý sự kiện và Yield
                xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                parsed_event = _parse_event_xml(xml)
                
                if "error" not in parsed_event:
                    yield parsed_event
                
                fetched_count += 1
                if fetched_count >= max_events:
                    break
            
            # Giữ thời gian nghỉ ngắn giữa các batch lớn
            time.sleep(0.5) 
            
    except Exception as e:
        logger.error(f"Error during reverse stream: {e}")
        yield {"error": f"Stream error: {e}"}
        
    finally:
        # 💡 BẮT BUỘC: Đóng Handle Query
        try:
            if handle:
                win32api.CloseHandle(handle)
                logger.info("Closed reverse query handle.")
        except Exception as e:
            logger.error(f"Error closing reverse query handle: {e}")