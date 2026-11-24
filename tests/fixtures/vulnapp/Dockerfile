FROM node:latest
ENV DB_PASSWORD=hunter2super
ADD https://example.com/app.tar.gz /opt/
RUN apt-get install -y curl
CMD ["node","server.js"]
