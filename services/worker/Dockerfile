FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    lynis \
    procps \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/worker

COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

CMD ["tail", "-f", "/dev/null"]
