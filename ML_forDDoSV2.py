import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

dataset_path = "./dataset/Selected_Features_Dataset.csv"  # เปลี่ยนเป็น path ของไฟล์ที่ใช้งาน
df = pd.read_csv(dataset_path, low_memory=False, dtype=str)  # โหลดข้อมูลเป็น string ทั้งหมด

selected_features = [
    "Application", "Repeat Count", "IP Protocol", "Bytes", "Bytes Sent", "Bytes Received",
    "Packets", "Elapsed Time (sec)", "Packets Sent", "Packets Received", "Session End Reason",
    "Risk of app", "Packets per second", "Bytes per second", "Average packet size"
]

string_features = ["Application", "Session End Reason"]
numeric_features = [col for col in selected_features if col not in string_features]

df_encoded = df[selected_features].copy()
label_encoders = {}
for col in string_features:
    le = LabelEncoder()
    df_encoded[col] = le.fit_transform(df_encoded[col].astype(str))
    label_encoders[col] = le

for col in numeric_features:
    df_encoded[col] = pd.to_numeric(df_encoded[col], errors='coerce')  # แปลงค่าไม่ได้ให้เป็น NaN

for col in numeric_features:
    df_encoded[col].fillna(df_encoded[col].median(), inplace=True)  # ใช้ค่ากลางเติมข้อมูลที่หายไป

label_mapping = {"Normal": 0, "DoS": 1, "DDoS": 2, "Slowloris": 3}
df_encoded["Label"] = df["Label"].map(label_mapping)

X = df_encoded.drop(columns=["Label"])
y = df_encoded["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

param_grid = {
    'n_estimators': [50, 100, 200],  # จำนวนต้นไม้
    'max_depth': [None, 10, 20, 30],  # ความลึกของต้นไม้
    'min_samples_split': [2, 5, 10],  # จำนวนตัวอย่างขั้นต่ำที่ต้องมีในการแบ่ง node
    'min_samples_leaf': [1, 2, 4]  # จำนวนตัวอย่างขั้นต่ำใน leaf node
}

grid_search = GridSearchCV(estimator=RandomForestClassifier(random_state=42), 
                           param_grid=param_grid, 
                           cv=3, 
                           n_jobs=-1,  
                           verbose=2)  

grid_search.fit(X_train, y_train)

best_params = grid_search.best_params_
best_score = grid_search.best_score_

print(f"🔍 Best Parameters: {best_params}")
print(f"✅ Best Model Score: {best_score:.4f}")

best_model = RandomForestClassifier(**best_params, random_state=42)
best_model.fit(X_train, y_train)

y_pred = best_model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f" Model Accuracy (Best Tuned): {accuracy:.4f}")
print("Classification Report:\n", classification_report(y_test, y_pred))

plt.figure(figsize=(6, 4))
conf_matrix = confusion_matrix(y_test, y_pred)
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", xticklabels=label_mapping.keys(), yticklabels=label_mapping.keys())
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix (Best Tuned Model)")
plt.show()

joblib.dump(best_model, "RandomForest_Traffic_ModelV2.pkl")
print("Best Model saved as Best_RandomForest_Traffic_Model.pkl")
