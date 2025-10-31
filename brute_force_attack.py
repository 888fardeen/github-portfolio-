import time

# Configuration
MAX_FAILED_ATTEMPTS = 4 # Maximum failed attempts allowed
OBSERVATION_WINDOW = 60  # Time window to track attempts (in seconds)
BLOCK_TIME = 300         # Block time for flagged IPs (in seconds)

# Data structures to track login attempts and blocked IPs
login_attempts = {}  # {IP: [(timestamp, success)]}
blocked_ips = {}     # {IP: block_expiry_timestamp}

def log_attempt(ip, success):
    """
    Log a login attempt and check for brute force attacks.
    
    Args:
        ip (str): IP address of the user.
        success (bool): Whether the login attempt was successful.

    Returns:
        bool: True if the IP is blocked, False otherwise.
    """
    current_time = time.time()

    # Check if the IP is already blocked
    if ip in blocked_ips:
        if current_time < blocked_ips[ip]:
            print(f"IP {ip} is blocked until {time.ctime(blocked_ips[ip])}.")
            return True
        else:
            # Unblock the IP after block time has expired
            del blocked_ips[ip]

    # Initialize or update the login attempts list for this IP
    if ip not in login_attempts:
        login_attempts[ip] = []

    # Log the current attempt
    login_attempts[ip].append((current_time, success))

    # Remove attempts outside the observation window
    login_attempts[ip] = [
        attempt for attempt in login_attempts[ip]
        if current_time - attempt[0] <= OBSERVATION_WINDOW
    ]

    # Count the number of failed attempts
    failed_attempts = [attempt for attempt in login_attempts[ip] if not attempt[1]]

    if len(failed_attempts) >= MAX_FAILED_ATTEMPTS:
        # Block the IP for exceeding the maximum failed attempts
        blocked_ips[ip] = current_time + BLOCK_TIME
        print(f"ALERT: Brute force detected! IP {ip} is blocked for {BLOCK_TIME} seconds.")
        return True

    return False

def main():
    """
    Main function to simulate login attempts and detect brute force attacks.
    """
    print("Brute Force Detection System (type 'exit' to quit)")
    while True:
        ip = input("Enter IP address: ").strip()
        if ip.lower() == "exit":
            break

        result = input("Was the login successful? (y/n): ").strip().lower()
        success = result == "y"

        if log_attempt(ip, success):
            print(f"IP {ip} is temporarily blocked.")
        else:
            print(f"IP {ip} is allowed.")

if __name__ == "__main__":
    main()
