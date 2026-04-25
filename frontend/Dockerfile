FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Expose Vite dev server port
EXPOSE 5173

# Start Vite server (binds to 0.0.0.0 so host can access it)
CMD ["npm", "run", "dev", "--", "--host"]
