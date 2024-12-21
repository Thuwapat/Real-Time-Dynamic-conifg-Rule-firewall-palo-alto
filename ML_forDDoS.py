import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load datasets 
icmp_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/traffic_logs_ICMP.csv")
tcp_syn_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/traffic_logs_SYN.csv")
udp_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/traffic_logs_UDP.csv")

# Add a label column for attack type 
icmp_data['attack_type'] = '0' # As ICMP
tcp_syn_data['attack_type'] = '1' # As TCP
udp_data['attack_type'] = '2' # As UDP

# Select features and combine datasets
features = ['src', 'dst', 'sport', 'dport', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'pkts_sent', 'pkts_received', 'elapsed']
combined_data = pd.concat([icmp_data[features + ['attack_type']], # Add Attack type feature for each data and combine them together
                           tcp_syn_data[features + ['attack_type']],
                           udp_data[features + ['attack_type']]])

# Handle missing values 
combined_data = combined_data.fillna(0)

# Encode categorical features (IP addresses)
combined_data = pd.get_dummies(combined_data, columns=['src', 'dst'], drop_first=True)

# Split data into features (X) and target (y)
X = combined_data.drop(columns=['attack_type'])
y = combined_data['attack_type']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

#******************************************************************************
# Train a Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
rf_classifier.fit(X_train, y_train)


# Save the trained model
with open('dos_detection_model.pkl', 'wb') as model_file:
    pickle.dump(rf_classifier, model_file)
#******************************************************************************

# Make predictions
y_pred = rf_classifier.predict(X_test)

# Evaluate the model
print("Classification Report:\n", classification_report(y_test, y_pred))
print("Accuracy Score:", accuracy_score(y_test, y_pred))