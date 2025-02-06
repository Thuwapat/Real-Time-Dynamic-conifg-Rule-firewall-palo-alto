import pandas as pd
import pickle

# Load the saved model
with open('dos_detection_model.pkl', 'rb') as model_file:
    loaded_model = pickle.load(model_file)

# Load new data
new_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/testML.csv")

# Define the features to be used
features = ['cps', 'kbps', 'num-active', 'num-icmp', 'num-tcp', 'num-udp', 'pps']
new_data = new_data[features]

# Drop non-numeric feature
non_numeric_columns = new_data.select_dtypes(include=['object']).columns
new_data = new_data.drop(columns=non_numeric_columns)

# Add 0 in missing Var !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
new_data = new_data.fillna(0)

# Align columns with the model's training features
new_data = new_data.reindex(columns=loaded_model.feature_names_in_, fill_value=0)

# Predict the attack type
predictions = loaded_model.predict(new_data)

# Add predictions to the new data ###############################
new_data['predicted_attack_type'] = predictions

# Count Attack_type 
attack_counts = new_data['predicted_attack_type'].value_counts().to_dict()

# Show attack type 
print("Attack type counts:")
for attack_type, count in attack_counts.items():
    print(f"Attack Type {attack_type}: {count}")
