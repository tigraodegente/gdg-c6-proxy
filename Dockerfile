FROM node:20-alpine

WORKDIR /app

COPY package.json server.js ./

RUN mkdir -p /tmp/certs

EXPOSE 8080

CMD ["node", "server.js"]
