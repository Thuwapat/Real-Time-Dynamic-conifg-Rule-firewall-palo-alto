import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load dataset!
normal_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/session_infoNormal_clean.csv") 
dos_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/session_infoDOS_clean.csv")
ddos_data = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/session_infoDDOS_clean.csv")
 
 # Add new column 
normal_data['state'] = '0' 
dos_data['state'] = '1' 
ddos_data['state'] = '2' 

# Feature use for train
features = ['cps', 'kbps', 'num-active', 'num-icmp', 'num-tcp', 'num-udp', 'pps']
combined_data = pd.concat([normal_data[features + ['state']], # Add Attack_type feature for each data and combine them together
                           dos_data[features + ['state']],
                           ddos_data[features + ['state']]])

# If Var Missing add 0 not Null allow!
combined_data = combined_data.fillna(0).astype(int)

# For check data
combined_data.to_csv('D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/combined_data.csv', index=False)


# Define x and y data
x = combined_data.drop(columns=['state'])
y = combined_data['state']

# Spilt data 
x_train, x_test, y_train, y_test = train_test_split(x, y.values, test_size=0.2, random_state=0)

#******************************************************************************

# Train a Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=10000, random_state=0)
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