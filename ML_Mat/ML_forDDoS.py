import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load dataset!
icmp_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/traffic_logs_ICMP.csv") 
tcp_syn_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/traffic_logs_SYN.csv")
udp_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/dataset/traffic_logs_UDP.csv")
 
 # Add new column 
icmp_data['attack_type'] = 'ICMP' 
tcp_syn_data['attack_type'] = 'TCP' 
udp_data['attack_type'] = 'UDP' 

# Feature use for train
features = ['sport', 'dport', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'pkts_sent', 'pkts_received', 'elapsed']
combined_data = pd.concat([icmp_data[features + ['attack_type']], # Add Attack_type feature for each data and combine them together
                           tcp_syn_data[features + ['attack_type']],
                           udp_data[features + ['attack_type']]])

# If Var Missing add 0 not Null allow!
combined_data = combined_data.fillna(0)

# For check data
#combined_data.to_csv('D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/combined_data.csv', index=False)


# Define x and y data
x = combined_data.drop(columns=['attack_type'])
y = combined_data['attack_type']

# Spilt data 
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=0)

#******************************************************************************

# Train a Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
rf_classifier.fit(x_train, y_train)

# Save the trained model
with open('dos_detection_model.pkl', 'wb') as model_file:
    pickle.dump(rf_classifier, model_file)

#******************************************************************************

# Make predict
y_pred = rf_classifier.predict(x_test)

# Score the model 
print("Classification Report:\n", classification_report(y_test, y_pred))
print("Accuracy Score:", accuracy_score(y_test, y_pred))