# Menggunakan python:3.12-slim sebagai base untuk ukuran image yang lebih kecil
FROM python:3.12-slim

LABEL maintainer="0xkatana"

# Set working directory
WORKDIR /app

# Install system dependencies gabungan
# - git (dari dockerfile 1)
# - tmate, openssh-client, wget, curl, nodejs, npm (dari dockerfile 2)
RUN apt-get update && apt-get install -y \
    git \
    tmate \
    openssh-client \
    wget \
    curl \
    nodejs \
    npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Dependency Python ---
# Copy requirements.txt untuk caching yang lebih baik
COPY requirements.txt .
# Install dependency python
RUN pip install --no-cache-dir -r requirements.txt

# --- Dependency Node.js ---
# Copy package.json
COPY package.json .
# Install dependency node
RUN npm install

# Copy seluruh kode (termasuk telegram_bot.py dan server.js)
COPY . .

# Expose port untuk server.js
EXPOSE 3000

# Jalankan keduanya: Node server di background (&) dan Python bot di foreground
CMD ["node", "server.js"]
