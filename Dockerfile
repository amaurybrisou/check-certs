FROM --platform=$BUILDPLATFORM golang:latest as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./

RUN export "GOOS=$(echo "$TARGETPLATFORM" | cut -d/ -f1)"; \
    export "GOARCH=$(echo "$TARGETPLATFORM" | cut -d/ -f2)"; \
    export CGO_ENABLED=0; \
    go build -o ./backend main.go

FROM node:alpine AS frontend

# Set the working directory
WORKDIR /app

RUN apk --no-cache add ca-certificates

# Copy the React app source code to the container
COPY ./front /app

# Install dependencies and build the React app
RUN npm install
RUN NODE_ENV=production npm run build

FROM --platform=$TARGETPLATFORM scratch

COPY --from=builder /app/backend /app/backend

COPY --from=frontend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=frontend /app/dist /app/dist

CMD ["/app/backend"]