# Start from the official lightweight Nginx image
FROM nginx:alpine

# Copy our custom Nginx configuration file
COPY default.conf /etc/nginx/conf.d/default.conf

# Copy a basic index.html file to serve
COPY index.html /usr/share/nginx/html/index.html

# Create an empty blocklist file so it exists on startup
RUN touch /etc/nginx/blocklist.conf