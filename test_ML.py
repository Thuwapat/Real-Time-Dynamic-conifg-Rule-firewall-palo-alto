import pandas as pd
import pickle

# Load the saved model
with open('dos_detection_model.pkl', 'rb') as model_file:
    loaded_model = pickle.load(model_file)

# Load new data 
new_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/test.csv") 

# Select features 
features = ['src', 'dst', 'sport', 'dport', 'bytes', 'bytes_sent', 'bytes_received', 
            'packets', 'pkts_sent', 'pkts_received', 'elapsed']

# Ensure only the necessary features are selected
if set(features).issubset(new_data.columns):
    new_data = new_data[features]
else:
    raise ValueError(f"The following features are missing from the new data: {set(features) - set(new_data.columns)}")

# Handle datetime or non-numeric columns if present
for column in new_data.columns:
    if new_data[column].dtype == 'object':
        try:
            #then drop a unnecessary feature casue error when paresing 
            new_data = new_data.drop(columns=[column])
        except:
            # If not datetime, leave for encoding or handle appropriately
            pass

# Fill missing values
new_data = new_data.fillna(0)

# Encode categorical features (e.g., IP addresses)
if 'src' in new_data.columns or 'dst' in new_data.columns:
    new_data = pd.get_dummies(new_data, columns=['src', 'dst'], drop_first=True)

# Align columns with the training data
new_data = new_data.reindex(columns=loaded_model.feature_names_in_, fill_value=0)

# Predict the attack type
predictions = loaded_model.predict(new_data)

# Add predictions to the new data
new_data['predicted_attack_type'] = predictions

# Count occurrences of each attack type
attack_counts = new_data['predicted_attack_type'].value_counts()
print("Attack type counts:\n", attack_counts)

