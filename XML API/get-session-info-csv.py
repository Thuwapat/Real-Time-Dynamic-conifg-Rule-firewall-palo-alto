import requests
import pandas as pd
import time
import os

# กำหนดค่าของ Firewall และ API Key
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
url = f"https://{firewall_ip}/api/"

# ฟังก์ชันสำหรับดึงข้อมูลจาก XML API
def fetch_session_info():
    params = {
        "type": "op",
        "key": api_key,
        "cmd": "<show><session><info></info></session></show>"
    }
    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Error fetching data: {response.status_code}")
        return None

# ฟังก์ชันสำหรับแปลง XML เป็น Dictionary
def parse_session_info(xml_data):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_data)
    result = root.find("result")
    if result is None:
        return {}
    
    # ดึงค่าทั้งหมดใน result และจัดเก็บใน dictionary
    session_info = {}
    for child in result:
        session_info[child.tag] = child.text
    
    return session_info

# ฟังก์ชันสำหรับบันทึกข้อมูลลงใน CSV
def save_to_csv(data, filename="session_info.csv"):
    """
    บันทึกข้อมูลลงไฟล์ CSV พร้อมสร้าง Header เฉพาะครั้งแรก
    """
    # แปลงข้อมูลเป็น DataFrame (1 แถว)
    df = pd.DataFrame([data])

    # ตรวจสอบว่าไฟล์มีอยู่หรือไม่
    try:
        with open(filename, "r", encoding="utf-8") as file:
            # หากไฟล์มีอยู่แล้ว ให้เพิ่มข้อมูลใหม่โดยไม่เขียน Header ซ้ำ
            df.to_csv(filename, mode="a", index=False, header=False, encoding="utf-8")
    except FileNotFoundError:
        # หากไฟล์ไม่มีอยู่ ให้สร้างไฟล์ใหม่พร้อม Header
        df.to_csv(filename, mode="w", index=False, header=True, encoding="utf-8")

# ฟังก์ชันหลัก: ดึงข้อมูลทุก 1 วินาที และบันทึกลง CSV
def main():
    print("Starting data collection...")
    while True:
        # ดึงข้อมูลจาก API
        xml_data = fetch_session_info()
        if xml_data:
            # แปลงข้อมูล XML เป็น Dictionary
            session_data = parse_session_info(xml_data)
            
            # บันทึกข้อมูลลง CSV
            save_to_csv(session_data)
            
            # แสดงข้อมูลใน Console
            print("Saved data:", session_data)
        
        # รอ 1 วินาทีก่อนดึงข้อมูลรอบถัดไป
        time.sleep(1)

# เริ่มต้นโปรแกรม
if __name__ == "__main__":
    main()
