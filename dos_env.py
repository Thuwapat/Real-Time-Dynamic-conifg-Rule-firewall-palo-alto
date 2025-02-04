import gym
import numpy as np
import pandas as pd
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

        
        self.num_samples = len(self.data)
        self.current_index = 0

        # Define Observation Space (7 Network Features)
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(7,), dtype=np.float32
        )

        # Define Action Space (3 Firewall Actions)
        self.action_space = spaces.Discrete(3)  # 3 actions: No Action, Apply DoS rules, Apply DDoS rules

        # Initialize State
        self.state = self.data.iloc[self.current_index, :-1].values
        self.steps = 0
        self.done = False

    def step(self, action):
        reward = 0

        # Get next data sample
        self.current_index = (self.current_index + 1) % self.num_samples
        self.state = self.data.iloc[self.current_index, :-1].values

        # Get attack type 
        attack_type = self.data.iloc[self.current_index, -1]  # 0 = Normal, 1 = DoS, 2 = DDoS

        # Reward system based on attack type
        if action == 0:  # No Action
            if attack_type == 0:
                reward = 0  # True Negative 
            else:
                reward = -1  # False Negative 

        elif action == 1:  # Apply DoS Rules
            if attack_type == 1:
                reward = 1  # True Positive 
            else:
                reward = -2 # False Positive

        elif action == 2:  # Apply DDoS Rules
            if attack_type == 2:
                reward = 1  # True Positive 
            else:
                reward = -2 # False Positive

        self.steps += 1
        self.done = self.steps >= self.num_samples  

        return self.state, reward, self.done, {}

    def reset(self):
        self.current_index = 0
        self.state = self.data.iloc[self.current_index, :-1].values
        self.steps = 0
        self.done = False
        return self.state
