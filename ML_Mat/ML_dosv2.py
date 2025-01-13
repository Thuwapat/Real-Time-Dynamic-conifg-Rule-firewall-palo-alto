import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

# Load datasets
dos_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/mod_datasetsdn.csv")

# Ensure all required features exist
required_features = ['src', 'dst', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'elapsed', 'attack_type', 'Protocol']
missing_features = set(required_features) - set(dos_data.columns)
if missing_features:
    raise ValueError(f"Missing features in dataset: {missing_features}")

# Filter the dataset to keep only the required features
dos_data = dos_data[required_features]

# Encode target variable
dos_data['attack_type'] = dos_data['attack_type'].map({'Benign': 0, 'DoS': 1}).fillna(-1)

# Handle missing values
dos_data = dos_data.fillna(0)

# Encode IP addresses
for col in ['src', 'dst']:
    le = LabelEncoder()
    dos_data[col] = le.fit_transform(dos_data[col])

# Encode 'Protocol' or any other string categorical column
if 'Protocol' in dos_data.columns:
    dos_data['Protocol'] = le.fit_transform(dos_data['Protocol'])

# Split data into features (X) and target (y)
X = dos_data.drop(columns=['attack_type'])
y = dos_data['attack_type']

# Split into train-test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

# Train Random Forest
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=0)
rf_classifier.fit(X_train, y_train)

# Save the model
with open('dos_detection_model.pkl', 'wb') as model_file:
    pickle.dump(rf_classifier, model_file)

# Evaluate the model
y_pred = rf_classifier.predict(X_test)
print("Classification Report:\n", classification_report(y_test, y_pred))
print("Accuracy Score:", accuracy_score(y_test, y_pred))
