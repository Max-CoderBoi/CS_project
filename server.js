const express = require("express");
const { createServer } = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*",
  },
});

// Store connected users: { username: { socketId, publicKey } }
const users = {};
// Store logged out or all registered hashes for simple auth
const registeredUsers = {}; // { username: hashedPassword }

// Logging function
function logSecure(message) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message}\n`;
  console.log(logEntry.trim());
  fs.appendFileSync("chat_logs.txt", logEntry);
}

io.on("connection", (socket) => {
  console.log(`[+] New connection: ${socket.id}`);

  // Authentication & Registration
  socket.on("register", ({ username, passwordHash, publicKey }, callback) => {
    if (users[username]) {
      return callback({ success: false, message: "User already online" });
    }

    if (registeredUsers[username] && registeredUsers[username] !== passwordHash) {
      return callback({ success: false, message: "Invalid credentials" });
    }

    // Register
    registeredUsers[username] = passwordHash;
    users[username] = { socketId: socket.id, publicKey };
    socket.username = username;

    logSecure(`User logged in: ${username}`);
    
    // Broadcast updated user list
    io.emit("user_list", Object.keys(users));
    callback({ success: true });
  });

  // Request public key of a specific user
  socket.on("request_public_key", (targetUsername, callback) => {
    if (users[targetUsername]) {
      callback({ publicKey: users[targetUsername].publicKey });
    } else {
      callback({ error: "User not found" });
    }
  });

  // Secure Key Exchange (Encrypted AES Key)
  socket.on("send_aes_key", ({ to, encryptedAesKey }) => {
    if (users[to]) {
      io.to(users[to].socketId).emit("receive_aes_key", {
        from: socket.username,
        encryptedAesKey
      });
      // Broadcast to MitM
      io.emit("mitm_intercept", {
        type: "Key Exchange",
        from: socket.username,
        to: to,
        payload: encryptedAesKey,
      });
      logSecure(`Encrypted AES Key sent from ${socket.username} to ${to} | Payload: ${encryptedAesKey.substring(0, 30)}...`);
    }
  });

  // Encrypted Message Transmission
  socket.on("send_message", ({ to, iv, encryptedMessage }) => {
    if (users[to]) {
      io.to(users[to].socketId).emit("receive_message", {
        from: socket.username,
        iv,
        encryptedMessage
      });
      // Broadcast to MitM visualizer
      io.emit("mitm_intercept", {
        type: "Message",
        from: socket.username,
        to: to,
        iv: iv,
        payload: encryptedMessage,
      });
      logSecure(`Message from ${socket.username} to ${to} | IV: ${iv} | Ciphertext: ${encryptedMessage.substring(0, 30)}...`);
    }
  });

  socket.on("disconnect", () => {
    if (socket.username) {
      delete users[socket.username];
      io.emit("user_list", Object.keys(users));
      logSecure(`User disconnected: ${socket.username}`);
    }
  });
});

const PORT = 3001;
httpServer.listen(PORT, () => {
  console.log(`Secure WebSocket server running on port ${PORT}`);
});
