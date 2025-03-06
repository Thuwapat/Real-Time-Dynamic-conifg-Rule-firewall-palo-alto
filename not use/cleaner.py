# Re-import necessary libraries and load the dataset again
import pandas as pd

# Load the dataset
new_file_path = './dataset/Balanced_datasetV3.csv'
new_data = pd.read_csv(new_file_path)

# Calculate the features
new_data['tcp_to_udp'] = new_data['num_tcp'] / new_data['num_udp'].replace(0, 1)  # Avoid division by zero
new_data['tcp_to_icmp'] = new_data['num_tcp'] / new_data['num_icmp'].replace(0, 1)
new_data['pps_to_cps'] = new_data['pps'] / new_data['cps'].replace(0, 1)
new_data['kbps_to_pps'] = new_data['kbps'] / new_data['pps'].replace(0, 1)
new_data['kbps_to_cps'] = new_data['kbps'] / new_data['cps'].replace(0, 1)
new_data['pps_to_cps'] = new_data['pps'] / new_data['cps'].replace(0, 1)

# Save the updated dataset to a new file
updated_file_path = './dataset/Updated_Balanced_dataset.csv'
new_data.to_csv(updated_file_path, index=False)

updated_file_path  # Provide the path for download
