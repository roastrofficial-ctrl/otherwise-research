FROM php:8.4-cli-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev libonig-dev libxml2-dev unzip git && docker-php-ext-install pdo_pgsql mbstring dom && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
WORKDIR /app
COPY composer.json composer.lock* ./
RUN composer install --no-dev --prefer-dist --no-interaction --no-scripts --no-progress
COPY . .
RUN mkdir -p bootstrap/cache storage/framework/cache storage/framework/sessions storage/framework/views storage/logs && chmod -R 700 storage
EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000", "-t", "public", "public/index.php"]
