from stable_baselines3 import PPO
from dos_env import DoSDetectionEnv
from stable_baselines3.common.vec_env import DummyVecEnv

dataset_path = "D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/combined_data.csv"

# Create RL Environment with Real Data
env = DummyVecEnv([lambda: DoSDetectionEnv(dataset_path)])  

# Optimized PPO Hyperparameters
model = PPO("MlpPolicy", env, device="cpu", verbose=1)

# Train RL Model with More Steps
model.learn(total_timesteps=5000000)  # Increase steps for better learning

# Save Optimized Model
model.save("dos_rl_agent")
print("RL Agent Trained")
