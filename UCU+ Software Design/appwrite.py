from appwrite.client import Client
from appwrite.services.account import Account

# Configure your Appwrite connection
client = Client()
client.set_endpoint('https://cloud.appwrite.io/v1')  # Appwrite endpoint
client.set_project('project-fra-6807d08800177b80f9c5')  # Your project ID

# Initialize Appwrite account
account = Account(client)

# Export the client and account instances
__all__ = ['client', 'account']