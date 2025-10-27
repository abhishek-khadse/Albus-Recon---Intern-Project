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

# Expose the Render port (Render uses PORT env var)
EXPOSE 5000

# Environment configuration
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Run Flask app with Gunicorn for production
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
