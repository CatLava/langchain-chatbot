# Use an official Python runtime as the base image
FROM python:3.9-slim


# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY .env /app/
COPY aws_tools.py /app/
COPY main.py /app/
COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt


# Run the chatbot when the container launches
CMD ["python", "main.py"]