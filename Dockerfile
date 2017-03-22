FROM golang:1.8.0-alpine

COPY . /go/src/dispatch
WORKDIR /go/src/dispatch
RUN apk add --update git ca-certificates &&\
   go get . &&\
   go test . &&\
   CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' .

CMD ["dispatch"]
