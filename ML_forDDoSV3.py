import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# 📌 โหลดข้อมูลที่ถูกเลือก
file_path = "./dataset/ML_Training_Dataset.csv"  # แก้เป็นชื่อไฟล์ของคุณ
df = pd.read_csv(file_path)

# 📌 จัดการค่าที่ขาดหายไป (ถ้ามี)
df = df.fillna(method='ffill')  # ใช้ค่าก่อนหน้าเติม (Forward Fill)

# 📌 แปลงข้อมูลประเภท Object ให้เป็นตัวเลข
label_encoders = {}
for col in df.select_dtypes(include=['object']).columns:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le  # เก็บ Label Encoder สำหรับใช้ภายหลัง

# 📌 แยก Features และ Label
X = df.drop(columns=['Label'])
y = df['Label']

# 📌 แบ่งข้อมูล Train และ Test (80:20)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 📌 สร้างและ Train โมเดล Random Forest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 📌 ทดสอบโมเดล
y_pred = rf_model.predict(X_test)

# 📌 ประเมินผลลัพธ์
accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)
class_report = classification_report(y_test, y_pred)

# 🔥 แสดงผลลัพธ์
print(f"🎯 Accuracy: {accuracy:.4f}")
print("\n📊 Confusion Matrix:\n", conf_matrix)
print("\n📑 Classification Report:\n", class_report)

# 📌 Export โมเดลเป็นไฟล์ .pkl
model_filename = "RandomForest_Traffic_ModelV3.pkl"
with open(model_filename, "wb") as model_file:
    pickle.dump(rf_model, model_file)

print(f"✅ โมเดลถูกบันทึกเป็นไฟล์ '{model_filename}' แล้ว!")

