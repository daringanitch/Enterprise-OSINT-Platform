FROM nginx:alpine

# Copy static files
COPY index.html /usr/share/nginx/html/
COPY health.html /usr/share/nginx/html/

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/health.html || exit 1

# Run nginx
CMD ["nginx", "-g", "daemon off;"]