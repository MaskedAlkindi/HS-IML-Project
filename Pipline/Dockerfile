# FROM python:3.11.9

# WORKDIR /app

# COPY requirements.txt .

# RUN apt-get update && apt-get install -y \
#     build-essential \
#     curl \
#     software-properties-common \
#     git \
#     && rm -rf /var/lib/apt/lists/*

# RUN pip install -r requirements.txt

# EXPOSE 8501

# COPY app/ ./app
# COPY prefect_flows/ ./prefect_flows

# HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health
# CMD ["streamlit", "run", "./app/streamlit_app.py"]


# Use the official Python image from the Docker Hub
FROM python:3.11.9

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any dependencies specified in requirements.txt
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install -r requirements.txt

# Expose the port Streamlit is running on
EXPOSE 8501

# Copy the application files into the container
COPY app/ ./app
COPY prefect_flows/ ./prefect_flows

# Create necessary directories
RUN mkdir -p /app/datasets
RUN mkdir -p /app/models

# Add a healthcheck to the container to make sure the service is running
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Command to run the Streamlit application
CMD ["streamlit", "run", "./app/streamlit_app.py"]
