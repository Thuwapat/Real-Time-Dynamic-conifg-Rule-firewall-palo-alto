import pandas as pd

df = pd.read_csv("D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/combined_data.csv")
print(df['state'].value_counts())  # ✅ Count of Normal, DoS, DDoS samples
