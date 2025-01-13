import paramiko

# Firewall credentials and details
firewall_ip = "192.168.15.5"  # Replace with the actual firewall IP
username = "admin"            # Replace with your username
password = "Zaza678#"    # Replace with your password
cli_command = "show rule-hit-count vsys vsys1"  # Command to get rule hit counts

def execute_ssh_command(host, user, passwd, command):
    """
    Connect to the firewall via SSH and execute a CLI command.
    """
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the firewall
        print(f"Connecting to {host}...")
        ssh.connect(host, username=user, password=passwd, timeout=10)
        
        # Execute the CLI command
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # Read the command output
        output = stdout.read().decode('utf-8')
        print(f"\nCommand Output:\n{output}")
        
        # Close the SSH connection
        ssh.close()
        print("Connection closed.")
    
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the function to execute the comman
execute_ssh_command(firewall_ip, username, password, cli_command)
