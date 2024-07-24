FROM python:3.11.9

WORKDIR /app

COPY requirements.txt .


RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    git \
    && rm -rf /var/lib/apt/lists/*


RUN pip install -r requirements.txt
EXPOSE 8501


COPY app/ ./app
COPY prefect_flows/ ./prefect_flows
# COPY .streamlit/config.toml /root/.streamlit/config.toml


HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health
CMD ["streamlit", "run", "./app/streamlit_app.py"]
