from stable_baselines3 import PPO
from dos_env import DoSDetectionEnv
from stable_baselines3.common.vec_env import DummyVecEnv

dataset_path = "D:/Real-Time-Dynamic-conifg-Rule-firewall-palo-alto/combined_data.csv"

# Create RL Environment with Real Data
env = DummyVecEnv([lambda: DoSDetectionEnv(dataset_path)])  

# Optimized PPO Hyperparameters
model = PPO(
    "MlpPolicy", env,
    device="cpu",
    n_steps=2048,             # Larger batch size
    batch_size=64,            # Stable updates
    learning_rate=3e-4,       # Slightly increased learning rate
    gamma=0.99,               # Long-term reward learning
    gae_lambda=0.95,          # Smoother advantage estimation
    clip_range=0.2,           # Increased clipping for better learning
    ent_coef=0.01,            # Balanced exploration
    vf_coef=0.3,              # Reduced value function impact
    max_grad_norm=0.5,        # Prevents large updates
    verbose=1
)

# Train RL Model with More Steps
model.learn(total_timesteps=2500000)  # Increase steps for better learning

# Save Optimized Model
model.save("dos_rl_agent")
print("RL Agent Trained with Optimized Settings!")
