import mysql.connector
from post_manager.settings import DATABASES

# Get database configuration from settings
db_config = DATABASES['default']

try:
    # Connect to MySQL without specifying a database
    connection = mysql.connector.connect(
        host=db_config['HOST'],
        user=db_config['USER'],
        password=db_config['PASSWORD'],
        port=db_config['PORT']
    )
    
    # Create database
    cursor = connection.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['NAME']}")
    print(f"Database '{db_config['NAME']}' created successfully")
    
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    if connection.is_connected():
        cursor.close()
        connection.close()
