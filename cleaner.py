import pandas as pd
import numpy as np

# 📌 **1. โหลด Dataset**
file_path = "./dataset/ML_Training_Dataset.csv"
df = pd.read_csv(file_path)

# 📌 **2. ลบฟีเจอร์ที่ไม่มีประโยชน์**
columns_to_drop = ["Application","Session End Reason"]
df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])

# 📌 **3. ตรวจหาคอลัมน์ที่เป็นข้อความ และใช้ Label Encoding**
#categorical_columns = df.select_dtypes(include=['object']).columns.tolist()
#label_encoders = {}
#for col in categorical_columns:
#    le = LabelEncoder()
#    df[col] = le.fit_transform(df[col])
#    label_encoders[col] = le  # เก็บ Label Encoder ไว้ใช้ภายหลัง

# 📌 **4. สร้างฟีเจอร์ใหม่ (Feature Engineering)**

# หลีกเลี่ยงการหารด้วยศูนย์
df["Packets per second"] = df["Packets"] / df["Elapsed Time (sec)"].replace(0, np.nan)
df["Bytes per second"] = df["Bytes"] / df["Elapsed Time (sec)"].replace(0, np.nan)
df["Bytes per packet"] = df["Bytes"] / df["Packets"].replace(0, np.nan)

df["Packets Sent Ratio"] = df["Packets Sent"] / df["Packets"].replace(0, np.nan)
df["Packets Received Ratio"] = df["Packets Received"] / df["Packets"].replace(0, np.nan)
df["Bytes Sent Ratio"] = df["Bytes Sent"] / df["Bytes"].replace(0, np.nan)
df["Bytes Received Ratio"] = df["Bytes Received"] / df["Bytes"].replace(0, np.nan)

# ใช้ Log Transformation กับค่าที่มีการกระจายแบบ Skewed
#for col in ["Bytes", "Packets", "Bytes Sent", "Bytes Received"]:
#    df[f"Log_{col}"] = np.log1p(df[col])

# 📌 **5. จัดการ Missing Values**
df.fillna(0, inplace=True)  # แทนที่ค่า NaN ด้วย 0

# 📌 **6. บันทึก Dataset ใหม่ที่ผ่าน Feature Engineering**
output_file_path = "./dataset/ML_Training_Dataset_Feature_Engineered.csv"
df.to_csv(output_file_path, index=False)

print(f"✅ Dataset ที่ผ่าน Feature Engineering ถูกบันทึกเป็นไฟล์: {output_file_path}")
