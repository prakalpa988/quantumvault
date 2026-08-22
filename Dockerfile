FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    ninja-build \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && mkdir /tmp/liboqs/build \
    && cd /tmp/liboqs/build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && ninja \
    && ninja install \
    && ldconfig \
    && rm -rf /tmp/liboqs

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN python seed_db.py

CMD uvicorn main:app --host 0.0.0.0 --port $PORT