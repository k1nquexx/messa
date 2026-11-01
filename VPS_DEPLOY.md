# Быстрый запуск мессенджера на твоем VPS (Ubuntu/Debian)

### 1. Подготовка VPS
Зайди на свой сервер по SSH и выполни:
```bash
sudo apt update && sudo apt install -y curl nodejs npm git ufw
# Создаем файл подкачки на 2 ГБ (чтобы 1 ГБ RAM никогда не закончился)
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 2. Клонирование и установка сервера
```bash
cd /opt
sudo git clone https://github.com/твой-репозиторий/sovereign-messenger.git # или скопируй папку проекта
cd sovereign-messenger/server
npm install
```

### 3. Запуск сервера с автоперезапуском (PM2)
```bash
sudo npm install -g pm2
# Задаем пароль сервера (поменяй 'supersecret123' на свой пароль для друзей):
export CIPHER_SERVER_SECRET="supersecret123"
export PORT=8080

pm2 start server.js --name "cipher-server" --env PORT=8080,CIPHER_SERVER_SECRET="supersecret123"
pm2 save
pm2 startup
```

### 4. Вечный бесплатный SSL и домен через Caddy (в 3 строчки)
Caddy сам бесплатно выпустит и продлит SSL-сертификат (HTTPS и WSS):
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy -y
```

Открой `/etc/caddy/Caddyfile`:
```
твой-домен.ru {
    reverse_proxy 127.0.0.1:8080
}
```
И перезапусти Caddy:
```bash
sudo systemctl restart caddy
```

Всё! Сервер будет работать 24/7 по защищенному адресу `https://твой-домен.ru` и `wss://твой-домен.ru`. Памяти будет кушать всего ~40 МБ.
