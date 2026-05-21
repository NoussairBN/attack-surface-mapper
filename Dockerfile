# Utiliser une image Python officielle
FROM python:3.12-slim

# Installer Java (nécessaire pour apktool) et apktool
RUN apt-get update && apt-get install -y \
    default-jre \
    apktool \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de travail
WORKDIR /app

# Copier les fichiers du projet
COPY . .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Commande par défaut pour la démo
ENTRYPOINT ["python3", "demo.py"]
