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

# Set default environment variables
ENV PORT=1276

# Expose the port defined in the environment variable
EXPOSE ${PORT}

# Run the Flask app using environment variables for configuration
ENTRYPOINT ["python", "discordata.py"]
CMD ["--key", "/certs/key.pem", "--cert", "/certs/cert.pem"]
