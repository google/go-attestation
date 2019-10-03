FROM golang:latest

RUN apt-get update && apt-get install -y \
    libtspi-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /go/src/app
COPY . .

RUN go test -i -v ./...

CMD cd attest && go test -v