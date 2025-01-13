import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder

# Load the trained model
with open('dos_detection_model.pkl', 'rb') as model_file:
    rf_classifier = pickle.load(model_file)

# Load the new dataset
new_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/test2.csv")

# Preprocess the new data to match the training format
# Ensure all necessary columns exist
required_features = ['src', 'dst', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'elapsed', 'Protocol']
missing_features = set(required_features) - set(new_data.columns)

if missing_features:
    raise ValueError(f"Missing features in new data: {missing_features}")

# Handle missing values
new_data = new_data.fillna(0)

# Encode IP addresses and Protocol
le = LabelEncoder()
for col in ['src', 'dst', 'Protocol']:
    if col in new_data.columns:
        # Convert all values to strings to handle mixed types
        new_data[col] = new_data[col].astype(str)
        new_data[col] = le.fit_transform(new_data[col])

# Drop any columns not used in training
X_new = new_data[required_features]

# Make predictions
predictions = rf_classifier.predict(X_new)

# Add predictions to the new_data dataframe
new_data['Predicted_Label'] = predictions

# Count the number of DoS and Benign predictions
dos_count = (new_data['Predicted_Label'] == 1).sum()
benign_count = (new_data['Predicted_Label'] == 0).sum()

# Print the counts
print(f"Number of DoS attacks detected: {dos_count}")
print(f"Number of Benign traffic instances detected: {benign_count}")

# Optional: Save the results to a new CSV file
new_data.to_csv("predicted_results.csv", index=False)
