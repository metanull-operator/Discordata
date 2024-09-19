# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to /app
COPY . .

# Define environment variable for the port
ENV PORT=1276

# Expose the port based on the environment variable
EXPOSE ${PORT}

# Run discordata.py with the specified command-line arguments
CMD ["python", "discordata.py", "--host=0.0.0.0", "--port=${PORT}"]
