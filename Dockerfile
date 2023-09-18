FROM node:14
WORKDIR /app
COPY package.json package.json
RUN npm install
COPY . .
EXPOSE 8001
CMD ["node", "server.js"]

