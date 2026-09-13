FROM docker.io/library/node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM docker.io/library/nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
# SPA history fallback + /api reverse proxy (PR 24A).
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80