#include "chat.h"
#include <iostream>
#include <algorithm>
#include <fmt/format.h>
#include "simple_json.h"  // Assume this header provides basic JSON utilities
#include <boost/beast/http.hpp>

ChatSession::ChatSession(tcp::socket&& socket, ChatRoom& room)
    : ws_(std::move(socket)), room_(room), closed_(false) {}

void ChatSession::start() {
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
        res.set(boost::beast::http::field::server, "ChatServer");
    }));
    ws_.async_accept([self = shared_from_this()](beast::error_code ec) {
        if (!ec) {
            std::cout << "[INFO] WebSocket accepted from a client.\n";
            self->readMessage();
        } else {
            std::cerr << "[ERROR] Accept error: " << ec.message() << "\n";
        }
    });
}

void ChatSession::send(const std::string& message) {
    if (closed_) return;
    net::post(ws_.get_executor(), [self = shared_from_this(), message]() {
        self->sendImpl(message);
    });
}

std::string ChatSession::get_username() const { return username_; }

void ChatSession::sendImpl(const std::string& message) {
    try {
        ws_.write(net::buffer(message));
        std::cout << "[INFO] Sent message: " << message << "\n";
    } catch (std::exception& e) {
        std::cerr << "[ERROR] Send error: " << e.what() << "\n";
        close();
    }
}

void ChatSession::readMessage() {
    ws_.async_read(buffer_, [self = shared_from_this()](beast::error_code ec, std::size_t) {
        if (ec) {
            std::cerr << "[WARN] Read error or connection closed: " << ec.message() << "\n";
            self->close();
            return;
        }
        std::string message = beast::buffers_to_string(self->buffer_.data());
        self->buffer_.consume(self->buffer_.size());
        std::cout << "[INFO] Received message: " << message << "\n";
        self->handleMessage(message);
        self->readMessage();
    });
}

void ChatSession::handleMessage(const std::string& message) {
    try {
        std::string type, user, content;
        if (simple_json::parse_message(message, type, user, content)) {
            if (type == "join") {
                if (!user.empty()) {
                    username_ = user;
                    room_.join(shared_from_this());
                    std::cout << "[INFO] User '" << username_ << "' joined the chat.\n";
                    std::string joinMsg = simple_json::make_message("system",
                        fmt::format("{} has joined the chat", username_));
                    room_.broadcast(joinMsg, shared_from_this());
                }
            } else if (type == "message" || type == "chat") {
                if (username_.empty()) {
                    std::string errorMsg = simple_json::make_message("error", "Join with a username first");
                    send(errorMsg);
                    return;
                }
                std::string chatMsg = simple_json::make_chat_message(username_, content);
                std::cout << "[INFO] Broadcasting message from '" << username_ << "': " << content << "\n";
                room_.broadcast(chatMsg, shared_from_this());
            }
        } else {
            // Fallback: treat non-JSON message as join or chat.
            if (username_.empty() && !message.empty()) {
                username_ = message;
                room_.join(shared_from_this());
                std::cout << "[INFO] User '" << username_ << "' auto-joined the chat.\n";
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

void ChatSession::close() {
    if (closed_.exchange(true))
        return;
    if (!username_.empty()) {
        std::cout << "[INFO] User '" << username_ << "' is disconnecting.\n";
        std::string leaveMsg = simple_json::make_message("system",
            fmt::format("{} has left the chat", username_));
        room_.broadcast(leaveMsg, shared_from_this());
        room_.leave(shared_from_this());
    }
    try {
        ws_.async_close(websocket::close_code::normal, [](beast::error_code) {});
    } catch (...) {}
}

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
            if (auto s = it->lock()) {
                actives.push_back(s);
                ++it;
            } else {
                it = sessions_.erase(it);
            }
        }
    }
    std::cout << "[INFO] Broadcasting message to " << actives.size() << " sessions.\n";
    for (auto& session : actives)
        session->send(message);
}
