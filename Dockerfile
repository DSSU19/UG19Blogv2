ARG NODE_VERSION=18.0.0

FROM node:${NODE_VERSION}-alpine
#Temporarily using development environment variable

ENV NODE_ENV development

WORKDIR /usr/src/app

# Copy package.json and package-lock.json first to leverage Docker cache
COPY package*.json ./

RUN npm install
# Expose the port that the application listens on
EXPOSE 8080

# Copy the rest of the source files into the image.
COPY . .

# Run the application.
CMD ["node", "server.js"]