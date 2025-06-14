# Utilisation d'une image Debian stable
FROM debian:bullseye-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    yara \
    exiftool \
    sleuthkit \
    libmagic1 \
    libyara-dev \
    git \
    net-tools \
    build-essential \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Configuration du répertoire de travail
WORKDIR /app

# Installation des dépendances Python
RUN pip3 install --no-cache-dir \
    requests \
    python-magic \
    yara-python \
    git+https://github.com/graingert/python-clamd.git@master \
    pycryptodome \
    pefile \
    capstone \
    volatility3 \
    distorm3 \
    psutil

# Configuration de ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 0.0.0.0" >> /etc/clamav/clamd.conf && \
    echo "LocalSocket /var/run/clamav/clamd.sock" >> /etc/clamav/clamd.conf && \
    echo "MaxFileSize 100M" >> /etc/clamav/clamd.conf && \
    echo "MaxScanSize 100M" >> /etc/clamav/clamd.conf && \
    freshclam || echo "Freshclam failed" && \
    chown -R clamav:clamav /var/lib/clamav

# Copie des fichiers
COPY forensic_analyzer.py .
COPY rules/malware.yar /app/rules/

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/output /app/input /app/rules && \
    chmod -R 755 /app

# Configuration de Volatility
RUN mkdir -p /root/.volatility && \
    echo "plugins=/usr/lib/python3/dist-packages/volatility/plugins" > /root/.volatility/volatilityrc

# Vérification des outils installés
RUN which clamd && \
    which yara && \
    which exiftool && \
    which fls && \
    which volatility3 || echo "Volatility3 not found in PATH"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC
ENV CLAMD_SOCKET=/var/run/clamav/clamd.sock
ENV CLAMD_TCP=localhost:3310

# Script de vérification de l'environnement
RUN echo '#!/bin/sh' > /app/check_env.sh && \
    echo 'echo "Vérification de l environnement..."' >> /app/check_env.sh && \
    echo 'echo "Python: $(python3 --version)"' >> /app/check_env.sh && \
    echo 'echo "ClamAV: $(which clamd)"' >> /app/check_env.sh && \
    echo 'echo "YARA: $(which yara)"' >> /app/check_env.sh && \
    echo 'echo "ExifTool: $(which exiftool)"' >> /app/check_env.sh && \
    echo 'echo "Sleuthkit: $(which fls)"' >> /app/check_env.sh && \
    echo 'echo "Volatility3: $(which volatility3)"' >> /app/check_env.sh && \
    echo 'echo "Répertoires:"' >> /app/check_env.sh && \
    echo 'ls -la /app' >> /app/check_env.sh && \
    echo 'ls -la /var/run/clamav' >> /app/check_env.sh && \
    chmod +x /app/check_env.sh

# Commande par défaut
CMD ["sh", "-c", "/app/check_env.sh && service clamav-daemon start && sleep 5 && python3 forensic_analyzer.py /app/input"] 
