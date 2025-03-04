import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# 📌 **โหลด Dataset**
dataset_path = "./dataset/Combined_Traffic_Dataset_With_Normal.csv"  # เปลี่ยนเป็น path ของไฟล์ที่ใช้งาน
df = pd.read_csv(dataset_path, low_memory=False, dtype=str)  # โหลดข้อมูลเป็น string ทั้งหมด

# 📌 **เลือก Features ที่ใช้**
selected_features = [
    "Application", "Repeat Count", "IP Protocol", "Bytes", "Bytes Sent", "Bytes Received",
    "Packets", "Elapsed Time (sec)", "Packets Sent", "Packets Received", "Session End Reason",
    "Risk of app", "Characteristic of app", "Packets per second", "Bytes per second", "Average packet size"
]

# 📌 **แยก Features เป็น Numeric และ String**
string_features = ["Application", "Session End Reason", "Characteristic of app"]
numeric_features = [col for col in selected_features if col not in string_features]

# 📌 **แปลง String Features เป็นตัวเลขโดยใช้ Label Encoding**
df_encoded = df[selected_features].copy()
label_encoders = {}
for col in string_features:
    le = LabelEncoder()
    df_encoded[col] = le.fit_transform(df_encoded[col].astype(str))
    label_encoders[col] = le

# 📌 **แปลงคอลัมน์ตัวเลขจาก string → numeric (จัดการ Mixed Data Type)**
for col in numeric_features:
    df_encoded[col] = pd.to_numeric(df_encoded[col], errors='coerce')  # แปลงค่าไม่ได้ให้เป็น NaN

# 📌 **แทนค่าหายไป**
for col in numeric_features:
    df_encoded[col].fillna(df_encoded[col].median(), inplace=True)  # ใช้ค่ากลางเติมข้อมูลที่หายไป

# 📌 **แทนค่า Label ตามที่กำหนด**
label_mapping = {"Normal": 0, "DoS": 1, "DDoS": 2, "Slowloris": 3}
df_encoded["Label"] = df["Label"].map(label_mapping)

# 📌 **แยก Features และ Target**
X = df_encoded.drop(columns=["Label"])
y = df_encoded["Label"]

# 📌 **แบ่งข้อมูลเป็น Train/Test (80:20)**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 📌 **กำหนดพารามิเตอร์สำหรับ GridSearchCV**
param_grid = {
    'n_estimators': [50, 100, 200],  # จำนวนต้นไม้
    'max_depth': [None, 10, 20, 30],  # ความลึกของต้นไม้
    'min_samples_split': [2, 5, 10],  # จำนวนตัวอย่างขั้นต่ำที่ต้องมีในการแบ่ง node
    'min_samples_leaf': [1, 2, 4]  # จำนวนตัวอย่างขั้นต่ำใน leaf node
}

# 📌 **สร้าง GridSearchCV**
grid_search = GridSearchCV(estimator=RandomForestClassifier(random_state=42), 
                           param_grid=param_grid, 
                           cv=3,  # Cross-validation 3 folds
                           n_jobs=-1,  # ใช้ทุก CPU core
                           verbose=2)  # แสดงผลการทำงาน

# 📌 **Train Grid Search**
grid_search.fit(X_train, y_train)

# 📌 **แสดงผลลัพธ์ที่ดีที่สุด**
best_params = grid_search.best_params_
best_score = grid_search.best_score_

print(f"🔍 Best Parameters: {best_params}")
print(f"✅ Best Model Score: {best_score:.4f}")

# 📌 **Train โมเดลด้วยพารามิเตอร์ที่ดีที่สุด**
best_model = RandomForestClassifier(**best_params, random_state=42)
best_model.fit(X_train, y_train)

# 📌 **ทำนายผลบนชุดทดสอบ**
y_pred = best_model.predict(X_test)

# 📌 **ประเมินผลลัพธ์**
accuracy = accuracy_score(y_test, y_pred)
print(f"🎯 Model Accuracy (Best Tuned): {accuracy:.4f}")
print("Classification Report:\n", classification_report(y_test, y_pred))

# 📌 **แสดง Confusion Matrix**
plt.figure(figsize=(6, 4))
conf_matrix = confusion_matrix(y_test, y_pred)
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", xticklabels=label_mapping.keys(), yticklabels=label_mapping.keys())
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix (Best Tuned Model)")
plt.show()

# 📌 **บันทึกโมเดลที่ดีที่สุด**
joblib.dump(best_model, "RandomForest_Traffic_ModelV1.pkl")
print("✅ Best Model saved as Best_RandomForest_Traffic_Model.pkl")
