FROM node:20-alpine

WORKDIR /app

# Копируем манифесты зависимостей
COPY package*.json ./

# Устанавливаем только production зависимости
RUN npm install --omit=dev

# Копируем файлы проекта
COPY . .

# Открываем порт сервера
EXPOSE 8080

# Переменные окружения по умолчанию
ENV PORT=8080
ENV NODE_ENV=production
ENV DISABLE_TUNNEL=true

# Точка входа
CMD ["node", "server/server.js"]
