#ifndef CHAT_H
#define CHAT_H

#include <memory>
#include <vector>
#include <mutex>
#include <atomic>
#include <string>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/beast/websocket.hpp>

namespace beast = boost::beast;
namespace websocket = boost::beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

class ChatSession;

class ChatRoom {
public:
    void join(std::shared_ptr<ChatSession> session);
    void leave(std::shared_ptr<ChatSession> session);
    void broadcast(const std::string& message, std::shared_ptr<ChatSession> sender);
private:
    std::mutex mtx_;
    std::vector<std::weak_ptr<ChatSession>> sessions_;
};

class ChatSession : public std::enable_shared_from_this<ChatSession> {
public:
    ChatSession(tcp::socket&& socket, ChatRoom& room);
    void start();
    void send(const std::string& message);
    std::string get_username() const;
private:
    void sendImpl(const std::string& message);
    void readMessage();
    void handleMessage(const std::string& message);
    void close();
private:
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    ChatRoom& room_;
    std::string username_;
    std::atomic<bool> closed_;
};

#endif
