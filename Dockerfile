FROM php:8-apache

# Apply security patches, build the PHP extensions, then remove the build-only
# packages (-dev headers plus the base image's compiler toolchain,
# $PHPIZE_DEPS and linux-libc-dev) so they don't ship in the final image.
# - gd: enable freetype + jpeg explicitly
# - ldap: use correct multiarch libdir (fixes "invalid host type: lib/x86_64-linux-gnu.2")
# - cleanup: the runtime libraries the extensions link against are found with
#   ldd and kept, so no Debian-release-specific package names are hardcoded
#   (same approach as the official php images).
RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y; \
    savedAptMark="$(apt-mark showmanual)"; \
    apt-get install -y --no-install-recommends \
        libldap2-dev libldap-common \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        dpkg-dev \
        gosu \
        unzip; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" gd; \
    multiarch="$(dpkg-architecture -q DEB_BUILD_MULTIARCH)"; \
    docker-php-ext-configure ldap --with-libdir="lib/${multiarch}"; \
    docker-php-ext-install -j"$(nproc)" ldap; \
    apt-mark auto '.*' > /dev/null; \
    apt-mark manual $savedAptMark libldap-common gosu unzip > /dev/null; \
    find /usr/local -type f -executable -exec ldd '{}' ';' 2>/dev/null \
      | awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
      | sort -u \
      | xargs -r dpkg-query --search \
      | awk 'sub(":$", "", $1) { print $1 }' \
      | sort -u \
      | xargs -r apt-mark manual; \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
        $PHPIZE_DEPS linux-libc-dev; \
    rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Enable Apache modules
RUN a2enmod rewrite ssl && a2dissite 000-default default-ssl

# Pre-bake Apache configuration
ENV SERVER_CERT_FILENAME=/ldap-user-manager/cert.crt
ENV SERVER_KEY_FILENAME=/ldap-user-manager/privkey.pem
ARG LDAP_SERVER_NAME=localhost
RUN set -eux; \
    echo "ServerName ${LDAP_SERVER_NAME}" >> /etc/apache2/apache2.conf; \
    { \
      echo "<VirtualHost *:80>"; \
      echo "  ServerName ${LDAP_SERVER_NAME}"; \
      echo "  Redirect permanent / https://${LDAP_SERVER_NAME}/"; \
      echo "</VirtualHost>"; \
    } > /etc/apache2/sites-enabled/redirect.conf; \
    { \
      echo "<VirtualHost *:443>"; \
      echo "  ServerName ${LDAP_SERVER_NAME}"; \
      echo "  DocumentRoot /opt/ldap_user_manager"; \
      echo "  <Directory /opt/ldap_user_manager>"; \
      echo "    Options -Indexes +FollowSymLinks"; \
      echo "    Require all granted"; \
      echo "  </Directory>"; \
      echo "  SSLEngine On"; \
      echo "  SSLCertificateFile /opt/ssl/${SERVER_CERT_FILENAME}"; \
      echo "  SSLCertificateKeyFile /opt/ssl/${SERVER_KEY_FILENAME}"; \
      echo "</VirtualHost>"; \
    } > /etc/apache2/sites-enabled/lum.conf; \
    { \
      echo "# Application state and internals must never be reachable over HTTP."; \
      echo "# DocumentRoot is /opt/ldap_user_manager, so data/ (session files, mTLS"; \
      echo "# tokens, audit logs, role presets, message store) would otherwise be"; \
      echo "# served as static files. Every one of these paths is read by PHP from"; \
      echo "# the filesystem; nothing fetches them over HTTP."; \
      echo "#"; \
      echo "# Staged mTLS downloads are unaffected: they are handed to the front"; \
      echo "# proxy via X-Accel-Redirect to /_protected_mtls/, which is served from"; \
      echo "# a separate /mtls_stage/ mount, not from DocumentRoot."; \
      echo "#"; \
      echo "# Matched on filesystem path, so this holds under any SERVER_PATH"; \
      echo "# prefix or Alias. Longer path than the DocumentRoot grant, so Apache"; \
      echo "# applies it last and it wins regardless of config load order."; \
      echo "<DirectoryMatch \"^/opt/ldap_user_manager/(data|includes|vendor)(/|\$)\">"; \
      echo "  Require all denied"; \
      echo "</DirectoryMatch>"; \
      echo ""; \
      echo "<FilesMatch \"^(composer\\.(json|lock)|\\.php-cs-fixer.*|\\.git.*|.*\\.inc\\.php)\$\">"; \
      echo "  Require all denied"; \
      echo "</FilesMatch>"; \
    } > /etc/apache2/conf-enabled/zz-lum-hardening.conf

# Expose ports
EXPOSE 80
EXPOSE 443

# Copy application files
COPY www/ /opt/ldap_user_manager

# Install PHP dependencies with Composer
COPY composer.json composer.lock* /opt/ldap_user_manager/
RUN cd /opt/ldap_user_manager && \
    composer install --no-dev --optimize-autoloader --no-interaction && \
    rm -f /usr/bin/composer && \
    apt-get purge -y --auto-remove unzip

# Add and set permissions for the entrypoint script
COPY entrypoint /usr/local/bin/entrypoint
RUN chmod a+x /usr/local/bin/entrypoint

# Set up /etc/ldap/ldap.conf during build to avoid runtime changes
ARG LDAP_TLS_CACERT=ca.crt
RUN mkdir -p /etc/ldap && \
    echo "TLS_CACERT /opt/ssl/${LDAP_TLS_CACERT}" > /etc/ldap/ldap.conf

# Security Note: This container is designed to run with a non-root user
# specified at runtime via docker-compose (user: UID:GID).
# The lack of USER directive in this Dockerfile is intentional - the user
# is set at the container runtime level for better security isolation.
# Apache will run as the specified non-root user without needing privilege dropping.
# See docker-compose.yml for the actual user configuration.
ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["apache2-foreground"]
