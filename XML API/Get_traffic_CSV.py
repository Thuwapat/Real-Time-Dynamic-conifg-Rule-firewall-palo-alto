import os
import json
import time
import pandas as pd
from Get_traffic import get_all_logs

# ดึงค่า api_key จาก environment variables
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

def save_to_csv(data, folder="dataset", filename="traffic_logs.csv"):
    # ตรวจสอบว่าโฟลเดอร์มีอยู่หรือไม่ ถ้าไม่มีให้สร้างใหม่
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, filename)
    
    # สมมุติว่า data เป็น list ของ dictionary
    df = pd.DataFrame(data)
    
    if os.path.exists(file_path):
        # Append ข้อมูลใหม่เข้าไปในไฟล์ CSV ที่มีอยู่แล้ว (ไม่บันทึก header)
        df.to_csv(file_path, mode="a", index=False, header=False, encoding="utf-8")
    else:
        # เขียนไฟล์ใหม่พร้อม header
        df.to_csv(file_path, mode="w", index=False, header=True, encoding="utf-8")
    
    print(f"Data saved to {file_path}")

def main():
    print("เริ่มดึง Traffic Log จาก Firewall...")
    logs = get_all_logs(api_key, log_type="traffic", max_logs=100)
    
    if logs:
        print("Retrieved logs:")
       # print(json.dumps(logs, indent=4))
        # บันทึก logs ลง CSV
        save_to_csv(logs, filename="traffic_logs.csv")
    else:
        print("ไม่สามารถดึง log ได้")

if __name__ == "__main__":
    main()