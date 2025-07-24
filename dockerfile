
# 🐍 Base image with Python and basic dependencies
FROM python:3.10-slim

# 🔒 Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 📁 Set working directory
WORKDIR /app

# 📦 Copy dependencies
COPY requirements.txt .

# ✅ Install dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# 📁 Copy all source code
COPY . .

# 🌐 Expose Gradio port
EXPOSE 7860

# 🚀 Run the app
CMD ["python", "ui/app.py"]

