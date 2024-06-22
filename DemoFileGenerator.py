import os

def generate_random_blob(file_path, size_in_mb):
    # Define the size in bytes
    size_in_bytes = size_in_mb * 1024 * 1024

    # Generate random bytes
    random_data = os.urandom(size_in_bytes)

    # Write the random bytes to a file
    with open(file_path, 'wb') as file:
        file.write(random_data)

    print(f"{size_in_mb}MB random blob created at: {file_path}")

# Specify the file path and size in MB
file_path = 'DEMO.bin'
size_in_mb = 2

# Generate the random blob
generate_random_blob(file_path, size_in_mb)
