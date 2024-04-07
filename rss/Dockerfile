FROM python:3.9

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your script
COPY rss_parser.py .

# Run your script
CMD ["python", "./rss_parser.py"]

