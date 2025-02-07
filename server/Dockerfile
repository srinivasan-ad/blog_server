FROM node:20


WORKDIR /app

COPY package*.json ./


RUN npm install --omit=dev


COPY . .


RUN npm run build


EXPOSE 5000


CMD ["sh", "-c", "PORT=$PORT DATABASE_URL=$DATABASE_URL JWT_SECRET_KEY=$JWT_SECRET_KEY JWT_EXPIRATION=$JWT_EXPIRATION npm run start"]
