# Stage 1: Build the Go application
FROM golang:1.16-alpine AS builder

WORKDIR /app

# Copy the Go module files and download dependencies first (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# ADD THIS LINE to fix the dependency issue before building
RUN go get github.com/gin-gonic/gin/binding@v1.8.1

# Build the Go application executable
# CGO_ENABLED=0 creates a static binary
# -o /app/tasky builds the output named 'tasky' in the /app directory
RUN CGO_ENABLED=0 go build -o /app/tasky .

# Stage 2: Create the final, minimal image
FROM alpine:latest

WORKDIR /app

# Copy only the compiled executable from the builder stage
COPY --from=builder /app/tasky .
# Copy the wizexercise.txt file
COPY wizexercise.txt .
# Copy necessary static assets if the app needs them (assuming 'assets' and 'views' folders)
COPY assets ./assets

# Expose the port the application will listen on (assuming 8080 for Go apps, check main.go if needed)
EXPOSE 8080

# The command to run the executable when the container starts
CMD ["./tasky"]
