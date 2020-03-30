FROM golang:1.12-alpine

COPY bin/portico .
COPY firebase-admin.json .

ENV PORT=80

EXPOSE ${PORT}

ENTRYPOINT ./portico --port ${PORT}
