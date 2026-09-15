FROM php:8.2-cli-alpine

WORKDIR /var/www/html

RUN apk update && apk add --no-cache \
    git \
    curl \
    libpng-dev \
    libxml2-dev \
    zip \
    unzip \
    oniguruma-dev \
    mysql-client

RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

COPY . .

# Run composer install if composer.json exists to generate autoloader
RUN if [ -f composer.json ]; then composer install --no-interaction --prefer-dist --optimize-autoloader --no-dev || true; fi

EXPOSE 8000

# Fallback entrypoint if artisan is not yet present
CMD sh -c "if [ -f artisan ]; then php artisan serve --host=0.0.0.0 --port=8000; else php -S 0.0.0.0:8000 -t public; fi"
