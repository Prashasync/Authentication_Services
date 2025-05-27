# Use a lightweight Node.js base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy dependency files first for optimized caching
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application (includes /src, /public, etc.)
COPY . .

# Build the app for production (optional: if you're using `npm start`, this may not be needed)
RUN npm run build

# Expose the port the app runs on
EXPOSE 4000

# Start the application
CMD ["npm", "start"]
