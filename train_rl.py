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
    n_steps=1024,             # Increase batch size for stable updates
    batch_size=64,            # Reduce batch size for smoother updates
    learning_rate=3e-4,      # Reduce learning rate for better stability
    gamma=0.99,               # Discount factor (higher for long-term learning)
    gae_lambda=0.95,          # Smoother advantage estimation
    clip_range=0.1,           # Smaller clipping to prevent instability
    ent_coef=0.02,            # Increase entropy coefficient for better exploration
    vf_coef=0.2,              # Reduce value function impact to decrease loss
    max_grad_norm=0.5,        # Prevent exploding gradients
    verbose=1
)

# Train RL Model with More Steps
model.learn(total_timesteps=500000)  # Increase steps for better learning

# Save Optimized Model
model.save("dos_rl_agent")
print("RL Agent Trained with Optimized Settings!")
