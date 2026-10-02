FROM golang:1.26-alpine

RUN apk add --no-cache git

WORKDIR /app

COPY . .

RUN go mod tidy

RUN cd cmd/tasks-server && CGO_ENABLED=0 GOOS=linux go build && cd -

EXPOSE 8080
CMD ["cmd/tasks-server/tasks-server"]
