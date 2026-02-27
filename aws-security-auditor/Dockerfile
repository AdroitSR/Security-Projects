FROM python:3.11-slim

WORKDIR /app

# Install AWS CLI (optional, for manual remediation)
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf aws awscliv2.zip \
    && apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aws_auditor.py aws_controls.json ./
COPY test_aws_auditor.py ./

RUN mkdir -p /app/reports

# Run as non-root
RUN useradd -m -u 1000 auditor && \
    chown -R auditor:auditor /app
USER auditor

ENTRYPOINT ["python", "aws_auditor.py"]
CMD ["--output-dir", "/app/reports"]