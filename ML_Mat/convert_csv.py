import pandas as pd

df = pd.read_parquet("D:/archive/Syn-training.parquet")
df.to_csv('Syn-training.csv')