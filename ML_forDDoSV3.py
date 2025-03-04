import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# 📂 โหลด Dataset
file_path = "./dataset/Balanced_Traffic_Dataset.csv"  # เปลี่ยนเป็นที่อยู่ของไฟล์คุณ
df = pd.read_csv(file_path)

# 🎯 ฟีเจอร์ที่เลือกใช้
selected_features = [
    "Repeat Count", "IP Protocol", "Bytes", "Bytes Sent", "Bytes Received",
    "Packets", "Elapsed Time (sec)", "Packets Sent", "Packets Received",
    "Risk of app", "Packets per second", "Bytes per second", "Average packet size", "Label"
]

df_selected = df[selected_features].copy()

# 🔄 แปลง Label เป็นตัวเลข
label_mapping = {"DoS": 1, "DDoS": 2, "Slowloris": 3}
df_selected["Label"] = df_selected["Label"].map(label_mapping)

# 🔄 แปลง 'IP Protocol' เป็นตัวเลข
df_selected["IP Protocol"] = df_selected["IP Protocol"].astype('category').cat.codes

# 🎯 แยก Features และ Label
X = df_selected.drop(columns=["Label"])
y = df_selected["Label"]

# ✂️ แบ่งข้อมูลเป็น Train (80%) และ Test (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 🌲 Train Random Forest Model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 🔮 ทำนายผล
y_pred = rf_model.predict(X_test)

# 📊 ประเมินผลลัพธ์
accuracy = accuracy_score(y_test, y_pred)
classification_rep = classification_report(y_test, y_pred, target_names=["DoS", "DDoS", "Slowloris"])
conf_matrix = confusion_matrix(y_test, y_pred)

print(f"🎯 Accuracy: {accuracy:.4f}")
print("\n📊 Classification Report:\n", classification_rep)

# 🔥 แสดงผล Confusion Matrix
plt.figure(figsize=(6, 5))
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", xticklabels=["DoS", "DDoS", "Slowloris"], yticklabels=["DoS", "DDoS", "Slowloris"])
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix for Random Forest Model")
plt.show()

# 💾 บันทึกโมเดล
model_filename = "Random_forest_modelV3.pkl"
joblib.dump(rf_model, model_filename)
print(f"✅ โมเดลถูกบันทึกแล้วที่: {model_filename}")
