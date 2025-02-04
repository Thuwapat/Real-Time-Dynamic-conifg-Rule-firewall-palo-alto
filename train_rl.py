from stable_baselines3 import PPO
from dos_env import DoSDetectionEnv
from stable_baselines3.common.vec_env import DummyVecEnv

dataset_path = "D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/combined_data.csv"

# Create RL Environment with Real Data
env = DummyVecEnv([lambda: DoSDetectionEnv(dataset_path)])  

model = PPO("MlpPolicy", env, device="cpu", verbose=1)

model.learn(total_timesteps=500000) 

model.save("dos_rl_agent")
print("RL Agent Trained")
