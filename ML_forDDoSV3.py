import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib

# 📌 **1. โหลด Dataset**
file_path = "./dataset/ML_Training_Dataset.csv"  # ระบุพาธของไฟล์ที่ดาวน์โหลด
df = pd.read_csv(file_path)

# 📌 **2. แปลง Label เป็นค่าตัวเลข**
label_mapping = {"Normal": 0, "DoS": 1, "DDoS": 2, "Slowloris": 3}
df["Label"] = df["Label"].map(label_mapping)

# 📌 **3. ตรวจหาคอลัมน์ที่เป็นข้อความ และใช้ Label Encoding**
categorical_columns = df.select_dtypes(include=['object']).columns.tolist()

# ใช้ Label Encoding กับทุกคอลัมน์ที่เป็นข้อความ
label_encoders = {}
for col in categorical_columns:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le  # เก็บตัว Encoder ไว้สำหรับใช้งานต่อไป

# 📌 **4. แยก Features และ Labels**
X = df.drop(columns=["Label"])  # Features
y = df["Label"]  # Target

# 📌 **5. แบ่ง Train/Test 80:20**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 📌 **6. Train Random Forest**
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 📌 **7. ทำนายผล**
y_pred = rf_model.predict(X_test)

acc = accuracy_score(y_pred, y_test)
print(acc)
# 📌 **8. แสดงผล Confusion Matrix**
plt.figure(figsize=(6,5))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=label_mapping.keys(), yticklabels=label_mapping.keys())
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()

# 📌 **9. แสดงผล Accuracy, Precision, Recall, F1-score**
print("📊 **Classification Report:**")
print(classification_report(y_test, y_pred))

# 📌 **10. บันทึกโมเดล และ Label Encoders**
model_filename = "RandomForest_Traffic_ModelV3.pkl"
encoder_filename = "LabelEncoders.pkl"

joblib.dump(rf_model, model_filename)
joblib.dump(label_encoders, encoder_filename)

print(f"✅ โมเดลถูกบันทึกเป็นไฟล์: {model_filename}")
print(f"✅ Label Encoders ถูกบันทึกเป็นไฟล์: {encoder_filename}")
