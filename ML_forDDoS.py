import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from check_importance import *


# Load datasets
#normal_data = pd.read_csv("./dataset/session_infoNormal_clean.csv") 
#dos_data = pd.read_csv("./dataset/session_infoDOS_clean.csv")
#ddos_data = pd.read_csv("./dataset/session_infoDDOS_clean.csv")
#
## Add target column
#normal_data['state'] = 0
#dos_data['state'] = 1
#ddos_data['state'] = 2

# Features for training
features = ['cps', 'kbps', 'num-active', 'num-icmp', 'num-tcp', 'num-udp', 'pps']
#combined_data = pd.concat([normal_data[features + ['state']],
#                           dos_data[features + ['state']],
#                           ddos_data[features + ['state']]])

combined_data = pd.read_csv("./dataset/train_dataset.csv")
combined_data = combined_data.fillna(0).astype(int)

combined_data.to_csv('./dataset/combined_data.csv', index=False)

# Define X and y
x = combined_data.drop(columns=['label'])
y = combined_data['label']

# Split data (adjusted test size for better generalization)
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.8, stratify=y, random_state=42)

# Optional: Feature Scaling (Uncomment if needed)
#scaler = StandardScaler()
#x_train_scaled = scaler.fit_transform(x_train)
#x_test_scaled = scaler.transform(x_test)

# Convert back to DataFrame (preserving feature names)
#x_train = pd.DataFrame(x_train_scaled, columns=x.columns)
#x_test = pd.DataFrame(x_test_scaled, columns=x.columns)

# Train a Random Forest Classifier (Optimized)
rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
rf_classifier.fit(x_train, y_train)


#with open('scaler.pkl', 'wb') as scaler_file:
#    pickle.dump(scaler, scaler_file)

# Save the trained model
with open('dos_detection_model.pkl', 'wb') as model_file:
    pickle.dump(rf_classifier, model_file)


# Make predictions
y_pred = rf_classifier.predict(x_test)

print("Classification Report:\n", classification_report(y_test, y_pred))
print("Accuracy Score:", accuracy_score(y_test, y_pred))
plot_feature_importance(rf_classifier, features)

