import gym
import numpy as np
import pandas as pd
import joblib
from gym import spaces
from sklearn.preprocessing import MinMaxScaler

class DoSDetectionEnv(gym.Env):
    # Load Env with real dataset
    def __init__(self, dataset_path):
        super(DoSDetectionEnv, self).__init__()

        # Load Dataset
        self.data = pd.read_csv(dataset_path)
        self.scaler = MinMaxScaler()
        
        # Identify feature columns
        feature_columns = self.data.columns[:-1]  

        # Convert only feature columns to float 
        self.data[feature_columns] = self.data[feature_columns].astype(float)
        
        # Apply MinMaxScaler only to numerical feature columns
        self.data[feature_columns] = self.scaler.fit_transform(self.data[feature_columns])
        
        joblib.dump(self.scaler, "scaler.pkl")
        self.num_samples = len(self.data)
        self.current_index = 0

        # Define Observation Space (7 Network Features)
        self.observation_space = spaces.Box(low=0, high=1, shape=(len(feature_columns),), dtype=np.float32)

        # Define Action Space (3 Firewall Actions)
        self.action_space = spaces.Discrete(3)  # 3 actions: No Action, Apply DoS rules, Apply DDoS rules

        # Initialize State
        self.state = self.data.iloc[self.current_index, :-1].values
        self.steps = 0
        self.done = False

    def step(self, action):
        reward = 0

        # Get next data sample
        self.current_index = np.random.randint(0, self.num_samples)
        self.state = self.data.iloc[self.current_index, :-1].values

        # Get attack type 
        attack_type = self.data.iloc[self.current_index, -1]  # 0 = Normal, 1 = DoS, 2 = DDoS

        if attack_type == 0:  # Normal traffic
            if action == 0:  
                reward = +1
            else:  
                reward = -1

        elif attack_type == 1:  # DoS Attack
            if action == 1: 
                reward = +1
            elif action == 0:  
                reward = -1
            else:  
                reward = -1

        elif attack_type == 2:  # DDoS Attack
            if action == 2:  
                reward = +1
            else:  
                reward = -1

        self.steps += 1
        self.done = self.steps >= self.num_samples  

        return self.state, reward, self.done, {}

    def reset(self):
        self.data = self.data.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle dataset
        self.current_index = 0
        self.state = self.data.iloc[self.current_index, :-1].values
        self.steps = 0
        self.done = False
        return self.state

