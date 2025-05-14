# Use Node.js Alpine base image
FROM node:alpine

# Create and set the working directory inside the container
WORKDIR /app

# Copy only package.json (no lock file)
COPY package.json ./

# Install dependencies
RUN npm install

# Copy the entire codebase to the working directory
COPY . /app/

# Expose the port your container app
EXPOSE 4000    

# Start your application
CMD ["npm", "start"]
