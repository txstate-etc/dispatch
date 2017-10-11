FROM golang:1-alpine
RUN apk add --update git ca-certificates

COPY . /go/src/dispatch
WORKDIR /go/src/dispatch
RUN go get .
RUN go test .
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' .

CMD ["dispatch"]
