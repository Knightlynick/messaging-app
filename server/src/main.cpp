#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <fmt/format.h>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>  // for setw, setfill

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// ---------------------------------------------------------------------------
// Simple JSON utility functions: These functions do a basic job of escaping
// strings and formatting messages in our minimal JSON protocol.
// ---------------------------------------------------------------------------
namespace simple_json {

    // Escape special characters in a string so that it is safe for JSON messages.
    std::string escape_string(const std::string& s) {
        std::ostringstream o;
        for (auto c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 32) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') 
                          << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    // Format a system message with a given type (e.g. "system", "error") and content.
    std::string make_message(const std::string& type, const std::string& content) {
        return fmt::format("{{\"type\":\"{}\",\"content\":\"{}\"}}", type, escape_string(content));
    }

    // Format a chat message including the sender's username.
    std::string make_chat_message(const std::string& username, const std::string& content) {
        return fmt::format("{{\"type\":\"chat\",\"username\":\"{}\",\"content\":\"{}\"}}",
                           escape_string(username), escape_string(content));
    }

    // Very basic JSON parser extracting "type", "username", and "content" from the input string.
    bool parse_message(const std::string& json, std::string& type, std::string& username, std::string& content) {
        bool has_type = false;
        size_t pos = json.find("\"type\":");
        if (pos != std::string::npos) {
            size_t start = json.find('"', pos + 7);
            if (start == std::string::npos) return false;
            start++;
            size_t end = json.find('"', start);
            if (end == std::string::npos) return false;
            type = json.substr(start, end - start);
            has_type = true;
        }

        pos = json.find("\"username\":");
        if (pos != std::string::npos) {
            size_t start = json.find('"', pos + 11);
            if (start != std::string::npos) {
                start++;
                size_t end = json.find('"', start);
                if (end != std::string::npos) {
                    username = json.substr(start, end - start);
                }
            }
        }

        pos = json.find("\"content\":");
        if (pos != std::string::npos) {
            size_t start = json.find('"', pos + 10);
            if (start != std::string::npos) {
                start++;
                size_t end = json.find('"', start);
                if (end != std::string::npos) {
                    content = json.substr(start, end - start);
                }
            }
        }
        return has_type;
    }
} // namespace simple_json

// ---------------------------------------------------------------------------
// Forward declaration of ChatSession for use in ChatRoom
// ---------------------------------------------------------------------------
class ChatSession;

// ---------------------------------------------------------------------------
// Global ChatRoom: Manages all connected client sessions.
// Provides functions to add a session (join), remove a session (leave),
// and broadcast messages to all active sessions.
// ---------------------------------------------------------------------------
class ChatRoom {
private:
    std::mutex mtx_;
    std::vector<std::weak_ptr<ChatSession>> sessions_;

public:
    // Add a new session to the chat room.
    void join(std::shared_ptr<ChatSession> session);

    // Remove a session from the chat room.
    void leave(std::shared_ptr<ChatSession> session);

    // Send the given message to all active sessions.
    void broadcast(const std::string& message, std::shared_ptr<ChatSession> sender);
};

// ---------------------------------------------------------------------------
// ChatSession: Represents one connection (client). Handles the handshake,
// reading messages, sending messages, and clean-up on disconnection.
// ---------------------------------------------------------------------------
class ChatSession : public std::enable_shared_from_this<ChatSession> {
private:
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    ChatRoom& room_;
    std::string username_;
    std::atomic<bool> closed_{false};

public:
    // Constructor: takes ownership of the socket and a reference to the chat room.
    ChatSession(tcp::socket&& socket, ChatRoom& room)
        : ws_(std::move(socket)), room_(room) {}

    // Start the session by performing the WebSocket handshake.
    void start() {
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(boost::beast::http::field::server, "ChatServer");
        }));
        ws_.async_accept([self = shared_from_this()](beast::error_code ec) {
            if (!ec) {
                std::cout << "[INFO] WebSocket accepted from a client." << "\n";
                self->readMessage();  // Begin reading messages after handshake.
            }
            else {
                std::cerr << "[ERROR] Accept error: " << ec.message() << "\n";
            }
        });
    }

    // Send a message to this client asynchronously.
    void send(const std::string& message) {
        if (closed_)
            return;
        net::post(ws_.get_executor(), [self = shared_from_this(), message]() {
            self->sendImpl(message);
        });
    }

    // Return the username associated with this session.
    std::string get_username() const { return username_; }

private:
    // Actually write the message to the socket.
    void sendImpl(const std::string& message) {
        try {
            ws_.write(net::buffer(message));
            std::cout << "[INFO] Sent message: " << message << "\n";
        } catch (std::exception& e) {
            std::cerr << "[ERROR] Send error: " << e.what() << "\n";
            close();
        }
    }

    // Read a message from the client asynchronously.
    void readMessage() {
        ws_.async_read(buffer_, [self = shared_from_this()](beast::error_code ec, std::size_t) {
            if (ec) {
                std::cerr << "[WARN] Read error or connection closed: " << ec.message() << "\n";
                self->close();
                return;
            }
            // Convert the buffer to a string.
            std::string message = beast::buffers_to_string(self->buffer_.data());
            self->buffer_.consume(self->buffer_.size());
            std::cout << "[INFO] Received message: " << message << "\n";
            // Process the incoming message
            self->handleMessage(message);
            // Continue reading for more messages.
            self->readMessage();
        });
    }

    // Process incoming messages based on the protocol.
    void handleMessage(const std::string& message) {
        try {
            std::string type, user, content;
            // Attempt to parse the input message.
            if (simple_json::parse_message(message, type, user, content)) {
                if (type == "join") {
                    // Process join request: set the username and add to chat room.
                    if (!user.empty()) {
                        username_ = user;
                        room_.join(shared_from_this());
                        std::cout << "[INFO] User '" << username_ << "' joined the chat." << "\n";
                        std::string joinMsg = simple_json::make_message("system",
                            fmt::format("{} has joined the chat", username_));
                        room_.broadcast(joinMsg, shared_from_this());
                    }
                } else if (type == "message") {
                    // If a user sends a message but hasn't joined, return an error.
                    if (username_.empty()) {
                        std::string errorMsg = simple_json::make_message("error", "Join with a username first");
                        send(errorMsg);
                        return;
                    }
                    // Format and broadcast the chat message.
                    std::string chatMsg = simple_json::make_chat_message(username_, content);
                    std::cout << "[INFO] Broadcasting message from '" << username_ << "': " << content << "\n";
                    room_.broadcast(chatMsg, shared_from_this());
                }
            } else {
                // Fallback: if not valid JSON, treat a nonempty message as a join or chat message.
                if (username_.empty() && !message.empty()) {
                    username_ = message;
                    room_.join(shared_from_this());
                    std::cout << "[INFO] User '" << username_ << "' auto-joined the chat." << "\n";
                    std::string joinMsg = simple_json::make_message("system",
                        fmt::format("{} has joined the chat", username_));
                    room_.broadcast(joinMsg, shared_from_this());
                } else if (!username_.empty() && !message.empty()) {
                    std::string chatMsg = simple_json::make_chat_message(username_, message);
                    std::cout << "[INFO] Broadcasting plain text message from '" << username_ << "': " << message << "\n";
                    room_.broadcast(chatMsg, shared_from_this());
                }
            }
        }
        catch (std::exception& e) {
            std::cerr << "[ERROR] Handle message error: " << e.what() << "\n";
        }
    }

    // Clean up and close the session, notifying the chat room.
    void close() {
        if (closed_.exchange(true))
            return;
        if (!username_.empty()) {
            std::cout << "[INFO] User '" << username_ << "' is disconnecting." << "\n";
            std::string leaveMsg = simple_json::make_message("system",
                fmt::format("{} has left the chat", username_));
            room_.broadcast(leaveMsg, shared_from_this());
            room_.leave(shared_from_this());
        }
        try {
            ws_.async_close(websocket::close_code::normal, [](beast::error_code) {
                // Connection closed normally.
            });
        }
        catch (...) { }
    }
};

// ---------------------------------------------------------------------------
// ChatRoom method implementations
// ---------------------------------------------------------------------------
void ChatRoom::join(std::shared_ptr<ChatSession> session) {
    std::lock_guard<std::mutex> lock(mtx_);
    sessions_.push_back(session);
    std::cout << "[INFO] ChatRoom: New session joined. Total sessions: " << sessions_.size() << "\n";
}

void ChatRoom::leave(std::shared_ptr<ChatSession> session) {
    std::lock_guard<std::mutex> lock(mtx_);
    sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(),
        [&](const std::weak_ptr<ChatSession>& ws) {
            auto s = ws.lock();
            return !s || s.get() == session.get();
        }), sessions_.end());
    std::cout << "[INFO] ChatRoom: Session left. Remaining sessions: " << sessions_.size() << "\n";
}

void ChatRoom::broadcast(const std::string& message, std::shared_ptr<ChatSession> sender) {
    std::vector<std::shared_ptr<ChatSession>> actives;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (auto s = it->lock())
                actives.push_back(s);
            else
                it = sessions_.erase(it);
            ++it;
        }
    }
    // Log broadcast event.
    std::cout << "[INFO] Broadcasting message to " << actives.size() << " sessions." << "\n";
    for (auto& session : actives) {
        session->send(message);
    }
}

// ---------------------------------------------------------------------------
// Listener: Accepts incoming TCP connections and creates a ChatSession for each
// connection. This class runs asynchronously.
// ---------------------------------------------------------------------------
class Listener : public std::enable_shared_from_this<Listener> {
private:
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    ChatRoom& room_;

public:
    Listener(net::io_context& ioc, tcp::endpoint endpoint, ChatRoom& room)
        : ioc_(ioc), acceptor_(ioc), room_(room) {
        beast::error_code ec;
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) { 
            std::cerr << "[ERROR] Open error: " << ec.message() << "\n"; 
            return; 
        }
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) { 
            std::cerr << "[ERROR] Option error: " << ec.message() << "\n"; 
            return; 
        }
        acceptor_.bind(endpoint, ec);
        if (ec) { 
            std::cerr << "[ERROR] Bind error: " << ec.message() << "\n"; 
            return; 
        }
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) { 
            std::cerr << "[ERROR] Listen error: " << ec.message() << "\n"; 
            return; 
        }
        std::cout << "[INFO] Listener initialized on " << endpoint << "\n";
    }

    // Begin to accept new connections.
    void run() {
        if (!acceptor_.is_open())
            return;
        doAccept();
    }

private:
    // Accept a new connection and create a new ChatSession.
    void doAccept() {
        acceptor_.async_accept([self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::cout << "[INFO] Accepted new connection from " << socket.remote_endpoint() << "\n";
                std::make_shared<ChatSession>(std::move(socket), self->room_)->start();
            } else {
                std::cerr << "[ERROR] Accept error: " << ec.message() << "\n";
            }
            self->doAccept();  // Continue accepting new connections.
        });
    }
};

// ---------------------------------------------------------------------------
// Main function: Entry point of the server. Sets up the listener, chat room,
// and io_context, then runs the event loop on multiple threads.
// ---------------------------------------------------------------------------
int main() {
    try {
        // Listen on all network interfaces, port 12345.
        const auto address = net::ip::make_address("0.0.0.0");
        unsigned short port = 12345;
        net::io_context ioc{1};

        // Global chat room instance.
        ChatRoom room;
        auto listener = std::make_shared<Listener>(ioc, tcp::endpoint{address, port}, room);
        listener->run();

        std::cout << "[INFO] Chat server started on port " << port << "\n";

        // Prepare worker threads.
        std::vector<std::thread> threads;
        auto thread_count = std::max(1u, std::thread::hardware_concurrency() - 1);
        for (unsigned i = 0; i < thread_count; ++i)
            threads.emplace_back([&ioc]{ ioc.run(); });

        // Run on the main thread as well.
        ioc.run();

        // Join all threads upon exit.
        for (auto& t : threads)
            t.join();
    } catch (std::exception& e) {
        std::cerr << "[ERROR] Main error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
