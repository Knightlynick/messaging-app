import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';

const socket = io("http://localhost:8080");

function App() {
  const [message, setMessage] = useState("");
  const [chat, setChat] = useState([]);

  useEffect(() => {
    socket.on("receive_message", (msg) => {
      setChat((prev) => [...prev, msg]);
    });
  }, []);

  const sendMessage = () => {
    socket.emit("send_message", message);
    setMessage("");
  };

  return (
    <div>
      <h2>Simple Messaging App</h2>
      <input type="text" value={message} onChange={(e) => setMessage(e.target.value)} />
      <button onClick={sendMessage}>Send</button>
      <div>
        {chat.map((msg, idx) => <div key={idx}>{msg}</div>)}
      </div>
    </div>
  );
}

export default App;