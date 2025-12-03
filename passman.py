import sys
import os

# Path to project directory
project_home = '/var/www/passman'

# Add the project directory to the Python path
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set the working directory
os.chdir(project_home)

# Import and create the Flask app
from app import create_app
application = create_app()