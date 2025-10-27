# Use official lightweight Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements first (for caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your backend files
COPY . .

# Expose Render’s dynamic port
EXPOSE 10000

# Environment configuration
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py

# Run Flask using the dynamic port assigned by Render
CMD ["python", "app.py"]
