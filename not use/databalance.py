import pandas as pd

def balance_dataset(file_path, sample_size=2500):
    # Load the dataset
    df = pd.read_csv(file_path, low_memory=False)
    
    # Sample data from each label
    dos_sample = df[df['Label'] == 'DoS'].sample(n=sample_size, random_state=42, replace=False)
    ddos_sample = df[df['Label'] == 'DDoS'].sample(n=sample_size, random_state=42, replace=False)
    slowloris_sample = df[df['Label'] == 'Slowloris'].sample(n=sample_size, random_state=42, replace=False)
    
    # Combine the sampled datasets
    balanced_df = pd.concat([dos_sample, ddos_sample, slowloris_sample], ignore_index=True)
    
    return balanced_df

# Example usage
file_path = "./dataset/Combined_Traffic_Dataset_DoS_DDoS_Slowloris.csv"
balanced_dataset = balance_dataset(file_path)

# Save or display the new balanced dataset
balanced_dataset.to_csv("./dataset/Balanced_Traffic_Dataset.csv", index=False)
