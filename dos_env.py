import gym
import numpy as np
import pandas as pd
from gym import spaces
from sklearn.preprocessing import MinMaxScaler

class DoSDetectionEnv(gym.Env):
    """ Custom RL Environment for DoS/DDoS Detection with Real Dataset """
    def __init__(self, dataset_path):
        super(DoSDetectionEnv, self).__init__()

        # Load Dataset
        self.data = pd.read_csv(dataset_path)
        self.scaler = MinMaxScaler()
        
        # Identify feature columns (excluding labels or categorical ones)
        feature_columns = self.data.columns[:-1]  # Assuming last column is the attack label

        # Convert only feature columns to float (keep other columns unchanged)
        self.data[feature_columns] = self.data[feature_columns].astype(float)

        # Apply MinMaxScaler only to numerical feature columns
        self.data[feature_columns] = self.scaler.fit_transform(self.data[feature_columns])

        
        self.num_samples = len(self.data)
        self.current_index = 0

        # Define Observation Space (7 Network Features)
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(7,), dtype=np.float32
        )

        # Define Action Space (4 Firewall Actions)
        self.action_space = spaces.Discrete(3)  # 4 actions: No Action, Apply DoS rules, Apply DDoS rules

        # Initialize State
        self.state = self.data.iloc[self.current_index, :-1].values
        self.steps = 0
        self.done = False

    def step(self, action):
        """ Take an action and return new state, reward, done, and info """
        reward = 0

        # Get next data sample
        self.current_index = (self.current_index + 1) % self.num_samples
        self.state = self.data.iloc[self.current_index, :-1].values

        # Get attack type (last column in dataset)
        attack_type = self.data.iloc[self.current_index, -1]  # 0 = Normal, 1 = DoS, 2 = DDoS

        # Reward system based on attack type
        if action == 0:  # Do Nothing it normal traffic
            reward = -5 if attack_type != 0 else 3 # High penalty if attack continues, small reward for normal traffic

        elif action == 1:  # Apply DoS Rules
            reward = 3 if attack_type == 1 else -5  # Reward for stopping DoS, but penalty if blocking normal traffic

        elif action == 2:  # Apply DDoS Rules
            reward = 3 if attack_type == 2 else -5  # Higher reward for DDoS, penalty for unnecessary action


        # Stop if max steps reached
        self.steps += 1
        self.done = self.steps >= self.num_samples  # End when dataset is exhausted

        return self.state, reward, self.done, {}

    def reset(self):
        """ Reset environment at the start of a new episode """
        self.current_index = 0
        self.state = self.data.iloc[self.current_index, :-1].values
        self.steps = 0
        self.done = False
        return self.state
