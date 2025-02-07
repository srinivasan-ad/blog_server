FROM node:20


WORKDIR /app

COPY package*.json ./


RUN npm install --omit=dev


COPY . .

COPY .env .env


RUN npm run build


EXPOSE 5000


CMD ["npm", "run", "start"]

