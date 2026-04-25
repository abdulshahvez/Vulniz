FROM node:20-alpine

WORKDIR /app

# Copy package files first to leverage Docker layer caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all source files
COPY . .

# Expose ports (Main API and Vulnerable API)
EXPOSE 3001
EXPOSE 3002

# Default command for development (starts main API)
CMD ["npm", "run", "dev"]
