import configparser
from cryptography.fernet import Fernet
import keyring
import base64

def encrypt_cisco_credentials(api_key, key_secret, config, configPath):
    """
    Encrypts Cisco Umbrella credentials (API key and key secret) using a Fernet key and stores them securely in the system's keyring.

    Args:
        api_key (str): The Cisco Umbrella API key to encrypt.
        key_secret (str): The Cisco Umbrella key secret to encrypt.
        config (ConfigParser): The configparser object containing configuration settings.
        config_path (str): The path to the configuration file.
    """

    # Generate a key for encryption
    key = Fernet.generate_key()
    fernet = Fernet(key)

    # Encrypt credentials
    encrypted_api_key = fernet.encrypt(api_key.encode())
    encrypted_key_secret = fernet.encrypt(key_secret.encode())

    encrypted_api_key_str = base64.b64encode(encrypted_api_key).decode()
    encrypted_key_secret_str = base64.b64encode(encrypted_key_secret).decode()
    key_str = base64.b64encode(key).decode()

    # Store encrypted credentials in keyring
    keyring.set_password("CISCO_UMBRELLA", "appId", encrypted_api_key_str)
    keyring.set_password("CISCO_UMBRELLA", "appSecret", encrypted_key_secret_str)
    keyring.set_password("CISCO_UMBRELLA", "key", key_str)

    # Clear credentials in config.ini
    config.set("CISCO_UMBRELLA", "appId", '')
    config.set("CISCO_UMBRELLA", "appSecret", '')
    with open(configPath, 'w') as config_file:
        config.write(config_file)


def get_encrypted_cisco_credentials():
    """
    Retrieves the encrypted Cisco Umbrella credentials from the system's keyring.

    Returns:
        tuple: A tuple containing the encrypted API key, encrypted key secret, and encryption key.
    """

    # Retrieve encrypted credentials from keyring
    encrypted_api_key_str = keyring.get_password("CISCO_UMBRELLA", "appId")
    encrypted_key_secret_str = keyring.get_password("CISCO_UMBRELLA", "appSecret")
    key_str = keyring.get_password("CISCO_UMBRELLA", "key")
    return encrypted_api_key_str, encrypted_key_secret_str, key_str


def get_decrypted_cisco_credentials(encrypted_api_key_str, encrypted_key_secret_str, key_str):
    """
    Decrypts the Cisco Umbrella credentials using the provided encryption key.

    Args:
        encrypted_api_key_str (str): The encrypted API key.
        encrypted_key_secret_str (str): The encrypted key secret.
        key_str (str): The encryption key.

    Returns:
        tuple: A tuple containing the decrypted API key and decrypted key secret.
    """

    encrypted_api_key = base64.b64decode(encrypted_api_key_str)
    encrypted_key_secret = base64.b64decode(encrypted_key_secret_str)
    key = base64.b64decode(key_str)
    
    # Decrypt credentials
    fernet = Fernet(key)
    api_key = fernet.decrypt(encrypted_api_key).decode()
    key_secret = fernet.decrypt(encrypted_key_secret).decode()
    return api_key, key_secret


# Read config.ini
config = configparser.ConfigParser()
configPath = 'config.ini'
config.read(configPath)

# Check if credentials are present in config.ini
api_key = config.get("CISCO_UMBRELLA", "appId")
key_secret = config.get("CISCO_UMBRELLA", "appSecret")

if api_key and key_secret:
    # Encrypt and store credentials
    encrypt_cisco_credentials(api_key, key_secret, config, configPath)

encrypted_api_key_str, encrypted_key_secret_str, key_str = get_encrypted_cisco_credentials()

if not encrypted_api_key_str or not encrypted_key_secret_str or not key_str:
    print('[Prerequisites] Please check the values: api_key, key_secret for CISCO in the configuration file')

else:
    print("App ID:", api_key)
    print("App Secret:", key_secret)