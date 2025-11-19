import time
import win32evtlog
import win32api
import xml.etree.ElementTree as ET
import os
from datetime import datetime
import logging
import sys

logger = logging.getLogger('agent.collector')

# --- CẤU HÌNH BOOKMARK ---
BOOKMARK_FILE = "sysmon_bookmark.xml"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
EVENT_LOG_QUERY = "*"


# --- CÁC HÀM HỖ TRỢ BOOKMARK AN TOÀN ---

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

# collector.py (Sửa lại)

# collector.py: Sửa hàm _get_bookmark_xml

def _get_bookmark_xml():
    """Tải chuỗi XML Bookmark từ file. Trả về None nếu không tồn tại hoặc lỗi."""
    if not os.path.exists(BOOKMARK_FILE):
        return None
    
    # 💡 Đọc bằng encoding chính xác
    with open(BOOKMARK_FILE, 'r', encoding='utf-8') as f:
        bookmark_xml = f.read()
        
    if not bookmark_xml:
        return None
        
    try:
        # 💡 ÉP KIỂU và LOẠI BỎ CÁC KÝ TỰ RỖNG/NGẮT DÒNG KHÔNG CẦN THIẾT
        # Sử dụng re.sub để loại bỏ các ký tự điều khiển (control characters)
        import re
        clean_xml = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', bookmark_xml).strip()

        logger.info(f"Loaded existing bookmark XML from {BOOKMARK_FILE}")
        return clean_xml
        
    except Exception as e:
        logger.error(f"Error processing bookmark XML: {e}")
        return None

def _save_bookmark_xml(bookmark_handle):
    """Lưu Handle Bookmark hiện tại vào file dưới dạng XML."""
    if not bookmark_handle:
        return
        
    # (Giữ nguyên hàm này)
    try:
        bookmark_xml = win32evtlog.EvtRender(
            bookmark_handle, 
            win32evtlog.EvtRenderBookmark
        )
        
        with open(BOOKMARK_FILE, 'w', encoding='utf-8') as f:
            f.write(bookmark_xml)
            
        logger.info(f"Bookmark saved to {BOOKMARK_FILE}")
    except Exception as e:
        logger.error(f"Failed to save bookmark: {e}")

# Giữ nguyên hàm _parse_event_xml (hàm phân tích XML)
# ...


# --- HÀM GENERATOR CHÍNH ---

def sysmon_event_stream(batch_size=100, poll_delay=0.1):
    """
    Generator function cho Sysmon events sử dụng EvtQuery và Bookmark.
    """
    query_handle = None
    update_handle = None
    
    # 1. Chuẩn bị Bookmark và Handle
    initial_bookmark_xml = _get_bookmark_xml()
    initial_bookmark_handle = None

    # 1. Thực hiện EvtQuery
    try:
        if initial_bookmark_xml:
            # 💡 CHỈ TẠO HANDLE TẠM THỜI (dùng để truy vấn) KHI CÓ XML
            initial_bookmark_handle = win32evtlog.EvtCreateBookmark(initial_bookmark_xml)
            logger.info("Created temporary handle for initial query position.")
            
        # 2. Thực hiện EvtQuery
        query_handle = win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            win32evtlog.EvtQueryForwardDirection, 
            EVENT_LOG_QUERY,
            initial_bookmark_handle # Truyền Handle Tạm thời (có thể là None)
        )
        logger.info("EvtQuery handle successfully created.")

    except Exception as e:
        logger.error(f"Failed to execute EvtQuery: {e}")
        yield {"error": f"EvtQuery failed: {e}"}
        return
        
    finally:
        # 💡 Đóng HANDLE TẠM THỜI NGAY LẬP TỨC nếu nó được tạo
        if initial_bookmark_handle:
            try:
                win32evtlog.CloseEventLog(initial_bookmark_handle)
                logger.info("Closed temporary initial bookmark handle.")
            except Exception as e:
                 logger.error(f"Error closing temporary bookmark handle: {e}")
    # 2. Vòng lặp Polling và Xử lý sự kiện
    try:
        while True:
            # 🛑 KIỂM TRA ĐIỀU KIỆN TẮT MÁY (Nếu bạn truyền cờ shutdown)
            # if shutdown_flag and shutdown_flag.is_set(): break
            
            events = None
            last_event_in_batch = None
            
            try:
                # EvtNext sẽ chặn tối đa 1000ms để đợi event mới
                events = win32evtlog.EvtNext(query_handle, batch_size, 1000)
                
            except win32api.error as e:
                # 259 (ERROR_NO_MORE_ITEMS) là bình thường khi hết backlog
                if e.winerror == 259: 
                    time.sleep(poll_delay)
                    continue
                else:
                    logger.error(f"EvtNext error (WinError {e.winerror}): {e}")
                    raise e
            except Exception as e:
                logger.error(f"EvtNext general error: {e}")
                raise e
            
            if not events:
                time.sleep(poll_delay)
                continue
            
            # 3. Xử lý Batch và Cập nhật Bookmark
            for ev in events:
                try:
                    # Parse Event (dùng hàm đã có của bạn, giả định hoạt động)
                    xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    parsed_event = _parse_event_xml(xml) 
                    
                    if "error" not in parsed_event:
                        yield parsed_event
                    else:
                        logger.warning(f"Skipping event due to parsing error: {parsed_event['error']}")
                        
                    last_event_in_batch = ev # Giữ lại handle của sự kiện cuối cùng

                except Exception as e:
                    logger.error(f"Event processing error: {e}")
                    # Không phá vỡ vòng lặp để tiếp tục xử lý các sự kiện còn lại

            # 💡 CẬP NHẬT VÀ LƯU BOOKMARK (SAU KHI XỬ LÝ XONG CẢ BATCH)
            if last_event_in_batch:
                try:
                    # 💡 TẠO UPDATE HANDLE MỚI TRONG VÒNG LẶP NẾU CẦN
                    # Tạo một handle Bookmark MỚI và TRỐNG CHỈ để cập nhật vị trí
                    temp_update_handle = win32evtlog.EvtCreateBookmark(None) 
                    
                    # Cập nhật vị trí
                    win32evtlog.EvtUpdateBookmark(temp_update_handle, last_event_in_batch)
                    
                    # Lưu XML ra file
                    _save_bookmark_xml(temp_update_handle)
                    
                    # 💡 ĐÓNG HANDLE CẬP NHẬT NGAY LẬP TỨC
                    win32evtlog.CloseEventLog(temp_update_handle)
                    
                except Exception as e:
                    logger.error(f"CRITICAL BOOKMARK ERROR: {e}")
                    raise Exception(f"Bookmark system failed: {e}")
                    
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt in event stream, stopping...")
        
    except Exception as e:
        logger.error(f"Critical stream error: {e}")
        yield {"error": f"Stream error: {e}"}
        
    finally:
        # 4. Dọn dẹp Handle Windows API
        logger.info("Closing handles.")
        
        # Đóng HANDLE QUERY
        if query_handle:
            win32evtlog.CloseEventLog(query_handle)
        
if __name__ == "__main__":
    count = 0
    for event in sysmon_event_stream():
        count += 1
        print("Count :", count)
