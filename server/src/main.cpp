#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>
#include <fmt/format.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <functional>

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

//------------------------------------------------------------------------------
// Simple JSON utilities.
namespace simple_json {
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
    std::string make_message(const std::string& type, const std::string& content) {
        return fmt::format("{{\"type\":\"{}\",\"content\":\"{}\"}}", type, escape_string(content));
    }
    std::string make_chat_message(const std::string& username, const std::string& content) {
        return fmt::format("{{\"type\":\"chat\",\"username\":\"{}\",\"content\":\"{}\"}}",
                           escape_string(username), escape_string(content));
    }
    std::string make_auth_response(bool success, const std::string& message = "") {
        return fmt::format("{{\"type\":\"auth\",\"status\":\"{}\",\"message\":\"{}\"}}",
                           success ? "success" : "failure", escape_string(message));
    }
}

namespace simple_json {
    // A very simplistic JSON parser that extracts the first occurrence of the keys "type", "username", and "content".
    bool parse_message(const std::string &json, std::string &type, std::string &username, std::string &content) {
        auto findKey = [&](const std::string &key) -> std::string {
            std::string pattern = "\"" + key + "\":\"";
            size_t start = json.find(pattern);
            if (start == std::string::npos)
                return "";
            start += pattern.size();
            size_t end = json.find("\"", start);
            if (end == std::string::npos)
                return "";
            return json.substr(start, end - start);
        };
        type = findKey("type");
        username = findKey("username");
        content = findKey("content");
        return !type.empty();  // if "type" is found, assume parsing was successful
    }
}


//------------------------------------------------------------------------------
// SHA-256 function using OpenSSL.
std::string sha256(const std::string& str) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to initialize SHA-256 digest");
    }
    if (EVP_DigestUpdate(context, str.c_str(), str.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to update digest");
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to finalize digest");
    }
    EVP_MD_CTX_free(context);
    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

//------------------------------------------------------------------------------
// User Database using SQLite.
class UserDatabase {
private:
    sqlite3* db_;
    std::mutex mtx_;
public:
    UserDatabase() : db_(nullptr) {
        int rc = sqlite3_open("chat_users.db", &db_);
        if (rc != SQLITE_OK) {
            std::cerr << "[ERROR] Can't open database: " << sqlite3_errmsg(db_) << "\n";
            return;
        }
        const char* sql = "CREATE TABLE IF NOT EXISTS users ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "username TEXT UNIQUE NOT NULL,"
                          "password_hash TEXT NOT NULL,"
                          "salt TEXT NOT NULL,"
                          "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);";
        char* errMsg = nullptr;
        rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "[ERROR] SQL error: " << errMsg << "\n";
            sqlite3_free(errMsg);
        }
    }
    ~UserDatabase() {
        if (db_) {
            sqlite3_close(db_);
        }
    }
    bool registerUser(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* checkSql = "SELECT username FROM users WHERE username = ?;";
        sqlite3_stmt* checkStmt;
        if (sqlite3_prepare_v2(db_, checkSql, -1, &checkStmt, nullptr) != SQLITE_OK) {
            std::cerr << "[ERROR] Prepare failed: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(checkStmt, 1, username.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(checkStmt) == SQLITE_ROW) {
            sqlite3_finalize(checkStmt);
            return false;
        }
        sqlite3_finalize(checkStmt);
        std::string salt = std::to_string(rand());
        std::string saltedPassword = password + salt;
        std::string hash = sha256(saltedPassword);
        const char* insertSql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?);";
        sqlite3_stmt* insertStmt;
        if (sqlite3_prepare_v2(db_, insertSql, -1, &insertStmt, nullptr) != SQLITE_OK) {
            std::cerr << "[ERROR] Prepare failed: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(insertStmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(insertStmt, 2, hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(insertStmt, 3, salt.c_str(), -1, SQLITE_STATIC);
        bool success = sqlite3_step(insertStmt) == SQLITE_DONE;
        sqlite3_finalize(insertStmt);
        return success;
    }
    bool authenticateUser(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql = "SELECT password_hash, salt FROM users WHERE username = ?;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[ERROR] Prepare failed: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        bool authenticated = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const char* salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string saltedPassword = password + salt;
            std::string computedHash = sha256(saltedPassword);
            authenticated = (computedHash == hash);
        }
        sqlite3_finalize(stmt);
        return authenticated;
    }
};

UserDatabase userDB;

//------------------------------------------------------------------------------
// Chat Room and Chat Session for WebSocket chat.
class ChatSession;
class ChatRoom {
private:
    std::mutex mtx_;
    std::vector<std::weak_ptr<ChatSession>> sessions_;
public:
    void join(std::shared_ptr<ChatSession> session);
    void leave(std::shared_ptr<ChatSession> session);
    void broadcast(const std::string& message, std::shared_ptr<ChatSession> sender);
};

class ChatSession : public std::enable_shared_from_this<ChatSession> {
private:
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    ChatRoom& room_;
    std::string username_;
    std::atomic<bool> closed_{false};
public:
    ChatSession(tcp::socket&& socket, ChatRoom& room)
        : ws_(std::move(socket)), room_(room) {}
    void start() {
        try {
            ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
            ws_.set_option(websocket::stream_base::decorator(
                [](websocket::response_type& res) {
                    res.set(http::field::server, "ChatServer");
                    res.set(http::field::access_control_allow_origin, "http://localhost:3000");
                    res.set(http::field::access_control_allow_methods, "POST, GET, OPTIONS");
                    res.set(http::field::access_control_allow_headers, "Content-Type");
                    res.set(http::field::access_control_allow_credentials, "true");
                }
            ));
            ws_.async_accept([self = shared_from_this()](beast::error_code ec) {
                try {
                    if (!ec) {
                        std::cout << "[INFO] WebSocket accepted from a client.\n";
                        self->readMessage();
                    } else {
                        std::cerr << "[ERROR] Accept error: " << ec.message() << "\n";
                    }
                } catch (std::exception &ex) {
                    std::cerr << "[EXCEPTION] In WebSocket accept handler: " << ex.what() << "\n";
                }
            });
        } catch (std::exception& e) {
            std::cerr << "[EXCEPTION] In ChatSession::start: " << e.what() << "\n";
        }
    }
    void send(const std::string& message) {
        if (closed_) return;
        net::post(ws_.get_executor(), [self = shared_from_this(), message]() {
            try {
                self->sendImpl(message);
            } catch (std::exception &ex) {
                std::cerr << "[EXCEPTION] In ChatSession send handler: " << ex.what() << "\n";
                self->close();
            }
        });
    }
    std::string get_username() const { return username_; }
private:
    void sendImpl(const std::string& message) {
        ws_.write(net::buffer(message));
        std::cout << "[INFO] Sent message: " << message << "\n";
    }
    void readMessage() {
        ws_.async_read(buffer_, [self = shared_from_this()](beast::error_code ec, std::size_t) {
            try {
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
            } catch (std::exception &ex) {
                std::cerr << "[EXCEPTION] In ChatSession read handler: " << ex.what() << "\n";
                self->close();
            }
        });
    }
    void handleMessage(const std::string& message) {
        try {
            // Try to parse the message as JSON.
            std::string type, userField, content;
            bool parsed = simple_json::parse_message(message, type, userField, content);
    
            if (parsed) {
                if (type == "join") {
                    // Instead of relying on the parser, explicitly extract the username.
                    size_t pos = message.find("\"username\":\"");
                    if (pos != std::string::npos) {
                        pos += strlen("\"username\":\"");
                        size_t end = message.find("\"", pos);
                        if (end != std::string::npos) {
                            username_ = message.substr(pos, end - pos);
                            std::cout << "[DEBUG] Extracted username from join: " << username_ << "\n";
                        }
                    }
                    if (!username_.empty()) {
                        room_.join(shared_from_this());
                        std::cout << "[INFO] User '" << username_ << "' joined the chat.\n";
                        std::string joinMsg = simple_json::make_message("system",
                            fmt::format("{} has joined the chat", username_));
                        room_.broadcast(joinMsg, shared_from_this());
                    } else {
                        std::cerr << "[ERROR] Failed to extract username from join message: " << message << "\n";
                    }
                }
                else if (type == "auth") {
                    // Process auth message. For example, if the content holds the login/register info:
                    std::istringstream iss(content);
                    std::string action, user, password;
                    iss >> action >> user >> password;
                    if (action == "login") {
                        if (userDB.authenticateUser(user, password)) {
                            username_ = user;
                            send(simple_json::make_auth_response(true));
                            room_.join(shared_from_this());
                            std::string joinMsg = simple_json::make_message("system",
                                fmt::format("{} has joined the chat", username_));
                            room_.broadcast(joinMsg, shared_from_this());
                        } else {
                            send(simple_json::make_auth_response(false, "Invalid credentials"));
                        }
                    } else if (action == "register") {
                        if (userDB.registerUser(user, password)) {
                            send(simple_json::make_auth_response(true));
                        } else {
                            send(simple_json::make_auth_response(false, "Username already exists"));
                        }
                    }
                }
                else if (type == "chat") {
                    if (username_.empty()) {
                        send(simple_json::make_auth_response(false, "Join with a username first"));
                        return;
                    }
                    std::string chatMsg = simple_json::make_chat_message(username_, content);
                    std::cout << "[INFO] Broadcasting message from '" << username_ << "': " << content << "\n";
                    room_.broadcast(chatMsg, shared_from_this());
                }
                else {
                    // If the type is not recognized, treat it as plain text chat if already joined.
                    if (!username_.empty()) {
                        std::string chatMsg = simple_json::make_chat_message(username_, message);
                        room_.broadcast(chatMsg, shared_from_this());
                    }
                }
            } else {
                // Not valid JSON: treat as plain text.
                if (username_.empty() && !message.empty()) {
                    // Auto-join with the provided message as username.
                    username_ = message;
                    room_.join(shared_from_this());
                    std::cout << "[INFO] User '" << username_ << "' auto-joined the chat.\n";
                    std::string joinMsg = simple_json::make_message("system",
                        fmt::format("{} has joined the chat", username_));
                    room_.broadcast(joinMsg, shared_from_this());
                } else if (!username_.empty() && !message.empty()) {
                    std::string chatMsg = simple_json::make_chat_message(username_, message);
                    room_.broadcast(chatMsg, shared_from_this());
                }
            }
        } catch (std::exception& e) {
            std::cerr << "[ERROR] Handle message error: " << e.what() << "\n";
        }
    }
    
    void close() {
        if (closed_.exchange(true)) return;
        if (!username_.empty()) {
            std::cout << "[INFO] User '" << username_ << "' is disconnecting.\n";
            std::string leaveMsg = simple_json::make_message("system",
                fmt::format("{} has left the chat", username_));
            room_.broadcast(leaveMsg, shared_from_this());
            room_.leave(shared_from_this());
        }
        try {
            ws_.async_close(websocket::close_code::normal, [](beast::error_code ec) {});
        } catch (...) {}
    }
};

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

void ChatRoom::broadcast(const std::string& message, std::shared_ptr<ChatSession> /*sender*/) {
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
    // Send to every connected session.
    for (auto& session : actives) {
        session->send(message);
    }
}


//------------------------------------------------------------------------------
// HTTP Authentication Session for handling /auth requests.
class HttpAuthSession : public std::enable_shared_from_this<HttpAuthSession> {
private:
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
public:
    HttpAuthSession(tcp::socket socket)
        : socket_(std::move(socket)) {}
    void run() {
        doRead();
    }
private:
    void doRead() {
        auto self = shared_from_this();
        http::async_read(socket_, buffer_, req_,
            [this, self](beast::error_code ec, std::size_t) {
                try {
                    if (!ec)
                        handleRequest();
                    else
                        std::cerr << "[ERROR] HTTP read: " << ec.message() << "\n";
                } catch (std::exception &ex) {
                    std::cerr << "[EXCEPTION] In HttpAuthSession doRead: " << ex.what() << "\n";
                }
            });
    }
    void handleRequest() {
        // Allocate a response object on the heap.
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
        
        // Clear default headers.
        res->base().clear();
    
        // Set minimal required headers explicitly.
        res->set(http::field::server, "MessagingApp");
        res->set(http::field::content_type, "application/json");
        res->set(http::field::access_control_allow_origin, "http://localhost:3000");
        res->set(http::field::access_control_allow_methods, "POST, GET, OPTIONS");
        res->set(http::field::access_control_allow_headers, "Content-Type");
        // Set the credential header explicitly using its literal name.
        res->set("Access-Control-Allow-Credentials", "true");
    
        std::string response_body;
        if (req_.target() == "/auth") {
            if (req_.method() == http::verb::options) {
                response_body = "";
            } else if (req_.method() == http::verb::post) {
                // Extract JSON fields from the request body.
                std::string body = req_.body();
                auto findValue = [&](const std::string & key) -> std::string {
                    std::string pattern = "\"" + key + "\":";
                    size_t pos = body.find(pattern);
                    if (pos != std::string::npos) {
                        size_t start = body.find("\"", pos + pattern.size());
                        if (start != std::string::npos) {
                            start++;
                            size_t end = body.find("\"", start);
                            if (end != std::string::npos) {
                                return body.substr(start, end - start);
                            }
                        }
                    }
                    return "";
                };
    
                std::string action = findValue("action");
                std::string username = findValue("username");
                std::string password = findValue("password");
    
                bool authSuccess = false;
                std::string message;
                if (action == "login") {
                    authSuccess = userDB.authenticateUser(username, password);
                    if (!authSuccess)
                        message = "Invalid credentials";
                } else if (action == "register") {
                    authSuccess = userDB.registerUser(username, password);
                    if (!authSuccess)
                        message = "Username already exists";
                } else {
                    message = "Unsupported action";
                }
    
                std::ostringstream oss;
                oss << "{\"type\":\"auth\",\"status\":\"" 
                    << (authSuccess ? "success" : "failure")
                    << "\",\"message\":\"" << message << "\"}";
                response_body = oss.str();
            } else {
                res->result(http::status::bad_request);
                response_body = "Unsupported HTTP method";
            }
        } else {
            res->result(http::status::not_found);
            response_body = "The resource was not found.";
        }
    
        res->body() = response_body;
        res->prepare_payload();
    
        auto self = shared_from_this();
        http::async_write(socket_, *res,
            [this, self, res](beast::error_code ec, std::size_t) {
                try {
                    socket_.shutdown(tcp::socket::shutdown_send, ec);
                } catch (...) {
                    // Ignore shutdown errors.
                }
            });
    }
    
    
    http::response<http::string_body> makeCorsResponse(http::status status, const std::string& bodyStr) {
        http::response<http::string_body> res{status, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.set(http::field::access_control_allow_origin, "http://localhost:3000");
        res.set(http::field::access_control_allow_methods, "POST, GET, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        res.set(http::field::access_control_allow_credentials, "true");
        res.body() = bodyStr;
        res.prepare_payload();
        return res;
    }
    http::response<http::string_body> badRequest(beast::string_view why) {
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "text/plain");
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    }
    http::response<http::string_body> notFound(beast::string_view target) {
        http::response<http::string_body> res{http::status::not_found, req_.version()};
        res.set(http::field::content_type, "text/plain");
        res.body() = "The resource '" + std::string(target) + "' was not found.";
        res.prepare_payload();
        return res;
    }
};

//------------------------------------------------------------------------------
// AuthListener: dedicated HTTP listener for /auth on port 8080.
class AuthListener : public std::enable_shared_from_this<AuthListener> {
private:
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
public:
    AuthListener(net::io_context& ioc, tcp::endpoint endpoint)
        : ioc_(ioc), acceptor_(ioc) {
        beast::error_code ec;
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            std::cerr << "[ERROR] AuthListener open error: " << ec.message() << "\n";
            return;
        }
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            std::cerr << "[ERROR] AuthListener set_option error: " << ec.message() << "\n";
            return;
        }
        acceptor_.bind(endpoint, ec);
        if (ec) {
            std::cerr << "[ERROR] AuthListener bind error: " << ec.message() << "\n";
            return;
        }
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            std::cerr << "[ERROR] AuthListener listen error: " << ec.message() << "\n";
            return;
        }
        std::cout << "[INFO] AuthListener initialized on " << endpoint << "\n";
    }
    void run() {
        doAccept();
    }
private:
    void doAccept() {
        acceptor_.async_accept([self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
            try {
                if (!ec) {
                    auto session = std::make_shared<HttpAuthSession>(std::move(socket));
                    session->run();
                } else {
                    std::cerr << "[ERROR] AuthListener accept error: " << ec.message() << "\n";
                }
                self->doAccept();
            } catch (std::exception &ex) {
                std::cerr << "[EXCEPTION] In AuthListener doAccept: " << ex.what() << "\n";
            }
        });
    }
};

//------------------------------------------------------------------------------
// ChatListener: dedicated WebSocket listener for chat on port 12345.
class ChatListener : public std::enable_shared_from_this<ChatListener> {
private:
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    ChatRoom& room_;
public:
    ChatListener(net::io_context& ioc, tcp::endpoint endpoint, ChatRoom& room)
        : ioc_(ioc), acceptor_(ioc), room_(room) {
        beast::error_code ec;
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            std::cerr << "[ERROR] ChatListener open error: " << ec.message() << "\n";
            return;
        }
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            std::cerr << "[ERROR] ChatListener set_option error: " << ec.message() << "\n";
            return;
        }
        acceptor_.bind(endpoint, ec);
        if (ec) {
            std::cerr << "[ERROR] ChatListener bind error: " << ec.message() << "\n";
            return;
        }
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            std::cerr << "[ERROR] ChatListener listen error: " << ec.message() << "\n";
            return;
        }
        std::cout << "[INFO] ChatListener initialized on " << endpoint << "\n";
    }
    void run() {
        doAccept();
    }
private:
    void doAccept() {
        acceptor_.async_accept([self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
            try {
                if (!ec) {
                    auto session = std::make_shared<ChatSession>(std::move(socket), self->room_);
                    session->start();
                } else {
                    std::cerr << "[ERROR] ChatListener accept error: " << ec.message() << "\n";
                }
                self->doAccept();
            } catch (std::exception &ex) {
                std::cerr << "[EXCEPTION] In ChatListener doAccept: " << ex.what() << "\n";
            }
        });
    }
};

//------------------------------------------------------------------------------
// Main function.
int main() {
    try {
        net::io_context ioc;
        // Create a work guard to prevent io_context from running out of work.
        auto work_guard = net::make_work_guard(ioc);
        ChatRoom room;
        auto authListener = std::make_shared<AuthListener>(
            ioc, tcp::endpoint(net::ip::make_address("0.0.0.0"), 8080));
        authListener->run();
        auto chatListener = std::make_shared<ChatListener>(
            ioc, tcp::endpoint(net::ip::make_address("0.0.0.0"), 12345), room);
        chatListener->run();
        std::cout << "[INFO] Auth server started on port 8080\n";
        std::cout << "[INFO] Chat server started on port 12345\n";
        
        // Launch worker threads.
        std::vector<std::thread> threads;
        unsigned thread_count = std::thread::hardware_concurrency();
        if(thread_count == 0) thread_count = 1;
        for (unsigned i = 0; i < thread_count; ++i)
            threads.emplace_back([&ioc]{ ioc.run(); });
        for (auto& t : threads)
            t.join();
    } catch (std::exception& e) {
        std::cerr << "[ERROR] Main error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
