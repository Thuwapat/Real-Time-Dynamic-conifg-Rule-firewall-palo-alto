import requests
import pandas as pd
import time

# กำหนดค่าของ Firewall และ API Key
firewall_ip = "192.168.15.5"
api_key = "LUFRPT1MNHgrYlFXcVc1bTYxa0F6TUNwZHdqL2lhaGM9cGRQSGNpeTFDWVA4cnlKcUFnaEQzaERMWVJyOWtVcnNuK3NVUWRSQ1MvVkFLYjJ1UXUxQ3ZCOHBrb25PU0hLeA=="
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
def save_to_csv(data, filename="session_infoNormal.csv"):
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

# ฟังก์ชันหลัก: ดึงข้อมูลทุกๆ 0.5 วินาที และทำงานนาน 15 นาที
def main():
    duration = 15 * 60  # 15 นาทีในหน่วยวินาที (15 * 60 = 900 วินาที)
    start_time = time.time()  # เวลาที่เริ่มต้นโปรแกรม

    print("Starting data collection for 15 minutes...")
    while True:
        # ตรวจสอบเวลาที่ผ่านไป
        elapsed_time = time.time() - start_time
        if elapsed_time > duration:
            print("Completed 15 minutes of data collection. Stopping now.")
            break  # ออกจากลูปเมื่อเวลาครบ 15 นาที

        # ดึงข้อมูลจาก API
        xml_data = fetch_session_info()
        if xml_data:
            # แปลงข้อมูล XML เป็น Dictionary
            session_data = parse_session_info(xml_data)
            
            # บันทึกข้อมูลลง CSV
            save_to_csv(session_data)
            
            # แสดงข้อมูลใน Console (สำหรับ Debugging)
            print("Saved data:", session_data)
        
        # รอ 0.5 วินาทีก่อนดึงข้อมูลรอบถัดไป
        time.sleep(0.25)

# เริ่มต้นโปรแกรม
if __name__ == "__main__":
    main()
