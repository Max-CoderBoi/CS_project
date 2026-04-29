"use client";

import { useState, useEffect, useRef } from "react";
import { io } from "socket.io-client";
import {
  generateRSAKeyPair,
  importRSAPublicKey,
  generateAESKey,
  exportAESKey,
  importAESKey,
  rsaEncrypt,
  rsaDecrypt,
  aesEncryptMessage,
  aesDecryptMessage,
  hashPassword,
} from "../utils/crypto";

export default function ChatApp() {
  const [socket, setSocket] = useState(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Crypto Keys
  const [keys, setKeys] = useState({ privateKey: null, publicKeyBase64: null });
  const [sharedAesKeys, setSharedAesKeys] = useState({}); // { targetUsername: AESKey }
  const sharedAesKeysRef = useRef(sharedAesKeys);

  useEffect(() => {
    sharedAesKeysRef.current = sharedAesKeys;
  }, [sharedAesKeys]);

  // Chat State
  const [users, setUsers] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState({}); // { username: [{ from, text, isEncrypted, rawData }] }
  const [inputMessage, setInputMessage] = useState("");

  // MitM Logs
  const [mitmLogs, setMitmLogs] = useState([]);
  const messagesEndRef = useRef(null);
  const mitmEndRef = useRef(null);

  // Auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeChat]);

  useEffect(() => {
    mitmEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [mitmLogs]);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!username || !password) return setError("Username and password required");

    setLoading(true);
    setError("");

    try {
      // 1. Generate RSA Keys for the user
      const rsaKeys = await generateRSAKeyPair();
      setKeys(rsaKeys);

      // 2. Hash password
      const passwordHash = await hashPassword(password);

      // 3. Connect to WebSocket Server
      const newSocket = io("http://localhost:3001");

      newSocket.on("connect", () => {
        newSocket.emit(
          "register",
          { username, passwordHash, publicKey: rsaKeys.publicKeyBase64 },
          (response) => {
            if (response.success) {
              setSocket(newSocket);
              setIsLoggedIn(true);
              setLoading(false);
            } else {
              setError(response.message);
              setLoading(false);
              newSocket.disconnect();
            }
          }
        );
      });

      // Socket Events
      newSocket.on("user_list", (userList) => {
        setUsers(userList.filter((u) => u !== username));
      });

      newSocket.on("receive_aes_key", async ({ from, encryptedAesKey }) => {
        try {
          const aesKeyBase64 = await rsaDecrypt(rsaKeys.privateKey, encryptedAesKey);
          const aesKey = await importAESKey(aesKeyBase64);
          setSharedAesKeys((prev) => ({ ...prev, [from]: aesKey }));
        } catch (err) {
          console.error("Failed to decrypt AES key from", from, err);
        }
      });

      newSocket.on("receive_message", async ({ from, iv, encryptedMessage }) => {
        // Wait briefly if AES key is arriving
        setTimeout(async () => {
          try {
            const aesKey = sharedAesKeysRef.current[from];
            if (!aesKey) {
              console.error("No AES key for", from);
              return;
            }

            const decryptedText = await aesDecryptMessage(aesKey, iv, encryptedMessage);
            setMessages((prev) => ({
              ...prev,
              [from]: [
                ...(prev[from] || []),
                { from, text: decryptedText, isEncrypted: false },
              ],
            }));
          } catch (err) {
            console.error("Decryption failed", err);
          }
        }, 100);
      });

      newSocket.on("mitm_intercept", (log) => {
        setMitmLogs((prev) => [...prev, { ...log, time: new Date().toLocaleTimeString() }]);
      });

    } catch (err) {
      setError("Crypto initialization failed");
      setLoading(false);
    }
  };

  const startChat = (targetUser) => {
    setActiveChat(targetUser);
    if (!sharedAesKeys[targetUser]) {
      // Initiate Key Exchange
      socket.emit("request_public_key", targetUser, async (res) => {
        if (res.publicKey) {
          const aesKey = await generateAESKey();
          const aesKeyBase64 = await exportAESKey(aesKey);
          const encryptedAesKey = await rsaEncrypt(
            await importRSAPublicKey(res.publicKey),
            aesKeyBase64
          );

          socket.emit("send_aes_key", { to: targetUser, encryptedAesKey });
          setSharedAesKeys((prev) => ({ ...prev, [targetUser]: aesKey }));
        }
      });
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || !activeChat || !sharedAesKeys[activeChat]) return;

    const textToSend = inputMessage;
    setInputMessage("");

    // Update local UI immediately
    setMessages((prev) => ({
      ...prev,
      [activeChat]: [
        ...(prev[activeChat] || []),
        { from: username, text: textToSend, isEncrypted: false },
      ],
    }));

    // Encrypt Message
    const aesKey = sharedAesKeys[activeChat];
    const { iv, ciphertext } = await aesEncryptMessage(aesKey, textToSend);

    // Send to Server
    socket.emit("send_message", {
      to: activeChat,
      iv: iv,
      encryptedMessage: ciphertext,
    });
  };

  if (!isLoggedIn) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <h1>SecureChat</h1>
          <p>Hybrid Encrypted (RSA + AES) Communication</p>
          {error && <div className="error-text">{error}</div>}
          <form onSubmit={handleLogin}>
            <div className="input-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div className="input-group">
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <button type="submit" className="btn" disabled={loading}>
              {loading ? <div className="loader"></div> : "Connect & Generate Keys"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>Logged in as {username}</h2>
          <p>RSA 2048-bit Key Pair Active</p>
        </div>
        <div className="user-list">
          {users.length === 0 ? (
            <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", textAlign: "center", marginTop: "2rem" }}>
              No other users online
            </p>
          ) : (
            users.map((u) => (
              <div
                key={u}
                className={`user-item ${activeChat === u ? "active" : ""}`}
                onClick={() => startChat(u)}
              >
                <span>{u}</span>
                <div className="status-dot"></div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="main-chat">
        {activeChat ? (
          <>
            <div className="chat-header">
              <h2>Chat with {activeChat}</h2>
              {sharedAesKeys[activeChat] ? (
                <div className="key-status secure">
                  <span title="AES Key Exchanged">🔒 AES-GCM 256-bit Secured</span>
                </div>
              ) : (
                <div className="key-status">
                  <span>Exchanging Keys...</span>
                </div>
              )}
            </div>

            <div className="messages-area">
              {(messages[activeChat] || []).map((msg, idx) => (
                <div key={idx} className={`message ${msg.from === username ? "sent" : "received"}`}>
                  <div className="message-bubble">
                    <span className="message-text">{msg.text}</span>
                  </div>
                  <div className="message-meta">
                    {msg.from === username ? "You" : msg.from}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

            <form className="chat-input" onSubmit={sendMessage}>
              <input
                type="text"
                placeholder="Type a secure message..."
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                disabled={!sharedAesKeys[activeChat]}
              />
              <button type="submit" disabled={!sharedAesKeys[activeChat] || !inputMessage.trim()}>
                Send
              </button>
            </form>
          </>
        ) : (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)" }}>
            Select a user to start a secure chat
          </div>
        )}
      </div>

      {/* MitM Wiretap Panel */}
      <div className="mitm-panel">
        <div className="mitm-header">
          <h2>⚠️ MitM Wiretap</h2>
          <p>Real-time view of intercepted network traffic</p>
        </div>
        <div className="mitm-logs">
          {mitmLogs.map((log, i) => (
            <div key={i} className="log-entry">
              <span className="log-time">[{log.time}]</span>
              <span className="log-title">{log.type} Intercepted</span>
              <div>From: {log.from} &rarr; To: {log.to}</div>
              {log.iv && <div>IV: <span className="log-highlight">{log.iv}</span></div>}
              <div style={{ marginTop: "0.5rem" }}>
                Payload: <span className="log-data">{log.payload.length > 100 ? log.payload.substring(0, 100) + "..." : log.payload}</span>
              </div>
            </div>
          ))}
          <div ref={mitmEndRef} />
        </div>
      </div>
    </div>
  );
}
