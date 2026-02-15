FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libssl-dev g++ curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY main.cpp .
RUN g++ -std=c++17 -O2 -o service-a main.cpp -lssl -lcrypto
EXPOSE 8080
CMD ["./service-a", "--cert", "/certs/cert.pem", "--key", "/certs/key.pem", "--ca", "/certs/chain.pem", "--port", "8080"]
