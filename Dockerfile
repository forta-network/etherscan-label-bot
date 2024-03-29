FROM alpine AS base

LABEL "network.forta.settings.agent-logs.enable"="true"
FROM golang:1.19.1 AS go-builder
WORKDIR /go/app
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . /go/app

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /go/app/main /go/app/main.go

FROM base
COPY --from=go-builder /go/app/main /main

EXPOSE 50051

CMD ["/main"]
