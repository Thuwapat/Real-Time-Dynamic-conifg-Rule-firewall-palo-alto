import numpy as np
import pandas as pd

# กำหนดจำนวน Normal Traffic ที่ต้องการสร้าง
num_normal_samples = 2500

balanced_df = pd.read_csv("./dataset/Balanced_Traffic_Dataset.csv")

# สร้าง DataFrame สำหรับ Normal Traffic โดยใช้คอลัมน์เดียวกับ Dataset เดิม
normal_traffic = pd.DataFrame({
    "Application": np.random.choice(balanced_df["Application"].dropna().unique(), num_normal_samples),
    "Repeat Count": np.random.randint(1, 5, num_normal_samples),
    "IP Protocol": np.random.choice([6, 17], num_normal_samples),  # TCP (6) หรือ UDP (17)
    "Bytes": np.random.randint(500, 20000, num_normal_samples),
    "Bytes Sent": np.random.randint(200, 10000, num_normal_samples),
    "Bytes Received": np.random.randint(200, 10000, num_normal_samples),
    "Packets": np.random.randint(10, 500, num_normal_samples),
    "Elapsed Time (sec)": np.random.uniform(0.5, 60, num_normal_samples),
    "Packets Sent": np.random.randint(5, 250, num_normal_samples),
    "Packets Received": np.random.randint(5, 250, num_normal_samples),
    "Session End Reason": np.random.choice(balanced_df["Session End Reason"].dropna().unique(), num_normal_samples),
    "Risk of app": np.random.randint(1, 2, num_normal_samples),  # ค่าความเสี่ยงต่ำ
    "Characteristic of app": np.random.choice(balanced_df["Characteristic of app"].dropna().unique(), num_normal_samples),
})

# คำนวณ Features Engineering เพิ่มเติม
normal_traffic["Packets per second"] = normal_traffic["Packets"] / (normal_traffic["Elapsed Time (sec)"] + 1e-5)
normal_traffic["Bytes per second"] = normal_traffic["Bytes"] / (normal_traffic["Elapsed Time (sec)"] + 1e-5)
normal_traffic["Average packet size"] = normal_traffic["Bytes"] / (normal_traffic["Packets"] + 1e-5)

# กำหนด Label เป็น "Normal"
normal_traffic["Label"] = "Normal"

# รวม Normal Traffic เข้ากับ Dataset ที่ปรับสมดุลแล้ว
combined_dataset_with_normal = pd.concat([balanced_df, normal_traffic], ignore_index=True)

# บันทึกไฟล์ CSV ใหม่
combined_with_normal_file_path = "./dataset/Combined_Traffic_Dataset_With_Normal.csv"
combined_dataset_with_normal.to_csv(combined_with_normal_file_path, index=False)

# ส่งไฟล์ให้ผู้ใช้ดาวน์โหลด
combined_with_normal_file_path
