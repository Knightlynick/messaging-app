/*
main.cpp
This file implements the backend server for a messaging app using Boost.Asio and Boost.Beast.
It provides an HTTP endpoint (/auth) for user authentication/registration and a WebSocket endpoint for chat.
User management is handled via SQLite with transactions (ACID properties) and concurrency is managed using a thread pool.
The app also includes a custom priority task scheduler for prioritizing tasks and uses timed_mutexes to help prevent deadlocks
*/

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
#include <queue>
#include <condition_variable>
#include <chrono>

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

/*
Enum for task priorities used in the custom scheduler
*/
enum class Priority {
    High = 0,
    Normal = 1,
    Low = 2
};

/*
Structure representing a scheduled task.
It contains a priority, a function to execute, and a sequence number for FIFO ordering.
*/
struct ScheduledTask {
    Priority priority;
    std::function<void()> func;
    uint64_t seq;
};

/*
Comparator for ScheduledTask that orders tasks by priority (lower numeric value is higher priority)
and uses the sequence number to preserve FIFO order for tasks with equal priority
*/
struct CompareTask {
    bool operator()(const ScheduledTask& a, const ScheduledTask& b) const {
        if (a.priority == b.priority)
            return a.seq > b.seq;
        return static_cast<int>(a.priority) > static_cast<int>(b.priority);
    }
};

/*
PriorityTaskScheduler schedules tasks based on priority. It maintains a priority queue of tasks
and runs a worker thread that waits for tasks and posts them to the io_context.
*/
class PriorityTaskScheduler {
private:
    std::priority_queue<ScheduledTask, std::vector<ScheduledTask>, CompareTask> tasks_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> stop_;
    uint64_t seqCounter_;
    net::io_context& ioc_;
    std::thread workerThread_;
public:
    /*
    Constructor that initializes the scheduler and starts the worker thread
    */
    PriorityTaskScheduler(net::io_context& ioc)
        : stop_(false), seqCounter_(0), ioc_(ioc) {
        workerThread_ = std::thread([this]() { this->run(); });
    }
    /*
    Destructor that signals the worker thread to stop and joins it
    */
    ~PriorityTaskScheduler() {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        if (workerThread_.joinable())
            workerThread_.join();
    }
    /*
    Schedules a task to be executed with the specified priority
    */
    void scheduleTask(Priority prio, std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            tasks_.push(ScheduledTask{prio, task, seqCounter_++});
        }
        cv_.notify_one();
    }
private:
    /*
    Worker thread function that waits for tasks and posts them to the io_context
    */
    void run() {
        while (!stop_) {
            ScheduledTask task;
            {
                std::unique_lock<std::mutex> lock(mtx_);
                cv_.wait(lock, [this]() { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty())
                    break;
                task = tasks_.top();
                tasks_.pop();
            }
            net::post(ioc_, task.func);
        }
    }
};

std::shared_ptr<PriorityTaskScheduler> g_scheduler;  // Global scheduler instance

/*
JSON utility functions for escaping strings and constructing JSON messages
*/
namespace simple_json {
    /*
    Escapes special characters in a string for JSON
    */
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
    /*
    Constructs a JSON message with a given type and content
    */
    std::string make_message(const std::string& type, const std::string& content) {
        return fmt::format("{{\"type\":\"{}\",\"content\":\"{}\"}}", type, escape_string(content));
    }
    /*
    Constructs a JSON chat message with username and content
    */
    std::string make_chat_message(const std::string& username, const std::string& content) {
        return fmt::format("{{\"type\":\"chat\",\"username\":\"{}\",\"content\":\"{}\"}}",
                           escape_string(username), escape_string(content));
    }
    /*
    Constructs a JSON authentication response with status and message
    */
    std::string make_auth_response(bool success, const std::string& message = "") {
        return fmt::format("{{\"type\":\"auth\",\"status\":\"{}\",\"message\":\"{}\"}}",
                           success ? "success" : "failure", escape_string(message));
    }
}

/*
A simple JSON parser that extracts the first occurrence of "type", "username", and "content"
*/
namespace simple_json {
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
        return !type.empty();
    }
}

/*
Computes the SHA-256 hash of a given string using OpenSSL
*/
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

/*
UserDatabase manages user registration and authentication using SQLite.
It uses a timed_mutex to prevent deadlocks and enables WAL mode for better concurrency.
*/
class UserDatabase {
private:
    sqlite3* db_;
    std::timed_mutex mtx_;
public:
    /*
    Constructor opens the database and creates the users table if it does not exist
    */
    UserDatabase() : db_(nullptr) {
        int rc = sqlite3_open("chat_users.db", &db_);
        if (rc != SQLITE_OK) {
            std::cerr << "[ERROR] Can't open database: " << sqlite3_errmsg(db_) << "\n";
            return;
        }
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
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
    /*
    Destructor closes the database connection
    */
    ~UserDatabase() {
        if (db_) {
            sqlite3_close(db_);
        }
    }
    /*
    Registers a user by inserting username, salted and hashed password into the database.
    Returns true if registration is successful.
    */
    bool registerUser(const std::string& username, const std::string& password) {
        std::unique_lock<std::timed_mutex> lock(mtx_, std::chrono::milliseconds(100));
        if (!lock.owns_lock()) {
            std::cerr << "[ERROR] registerUser: Failed to acquire lock (possible deadlock)" << "\n";
            return false;
        }
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
    /*
    Authenticates a user by comparing the provided password (after salting and hashing) with the stored hash.
    Returns true if the authentication is successful.
    */
    bool authenticateUser(const std::string& username, const std::string& password) {
        std::unique_lock<std::timed_mutex> lock(mtx_, std::chrono::milliseconds(100));
        if (!lock.owns_lock()) {
            std::cerr << "[ERROR] authenticateUser: Failed to acquire lock (possible deadlock)" << "\n";
            return false;
        }
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

// Forward declaration of ChatSession so that ChatRoom can reference it
class ChatSession;

/*
ChatRoom manages the chat sessions.
It allows sessions to join, leave, and broadcasts messages to all sessions.
A timed_mutex is used to prevent deadlocks.
Member function definitions for join, leave, and broadcast are provided after the full ChatSession definition.
*/
class ChatRoom {
private:
    std::timed_mutex mtx_;
    std::vector<std::weak_ptr<ChatSession>> sessions_;
public:
    void join(std::shared_ptr<ChatSession> session);
    void leave(std::shared_ptr<ChatSession> session);
    void broadcast(const std::string& message, std::shared_ptr<ChatSession> sender);
};

/*
ChatSession represents a WebSocket connection with a chat client.
It handles receiving, processing, and sending messages.
It also informs the ChatRoom when a user joins or leaves.
*/
class ChatSession : public std::enable_shared_from_this<ChatSession> {
private:
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    ChatRoom& room_;
    std::string username_;
    std::atomic<bool> closed_{false};
public:
    /*
    Constructor that initializes the session with a socket and a reference to the ChatRoom
    */
    ChatSession(tcp::socket&& socket, ChatRoom& room)
        : ws_(std::move(socket)), room_(room) {}
    /*
    Starts the WebSocket session by setting options and accepting the connection
    */
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
                        std::cout << "[INFO] WebSocket accepted from a client" << "\n";
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
    /*
    Sends a message asynchronously to the client
    */
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
    /*
    Returns the username associated with this session
    */
    std::string get_username() const { return username_; }
private:
    /*
    Low-level send implementation over the WebSocket
    */
    void sendImpl(const std::string& message) {
        ws_.write(net::buffer(message));
        std::cout << "[INFO] Sent message: " << message << "\n";
    }
    /*
    Asynchronously reads messages from the WebSocket and processes them
    */
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
    /*
    Processes an incoming message. Handles join, auth, chat, and plain text messages.
    */
    void handleMessage(const std::string& message) {
        try {
            std::string type, userField, content;
            bool parsed = simple_json::parse_message(message, type, userField, content);
    
            if (parsed) {
                if (type == "join") {
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
                        std::cout << "[INFO] User '" << username_ << "' joined the chat" << "\n";
                        std::string joinMsg = simple_json::make_message("system",
                            fmt::format("{} has joined the chat", username_));
                        room_.broadcast(joinMsg, shared_from_this());
                    } else {
                        std::cerr << "[ERROR] Failed to extract username from join message: " << message << "\n";
                    }
                }
                else if (type == "auth") {
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
                    if (!username_.empty()) {
                        std::string chatMsg = simple_json::make_chat_message(username_, message);
                        room_.broadcast(chatMsg, shared_from_this());
                    }
                }
            } else {
                if (username_.empty() && !message.empty()) {
                    username_ = message;
                    room_.join(shared_from_this());
                    std::cout << "[INFO] User '" << username_ << "' auto-joined the chat" << "\n";
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
    /*
    Closes the WebSocket connection and notifies the ChatRoom that this session is disconnecting
    */
    void close() {
        if (closed_.exchange(true))
            return;
        if (!username_.empty()) {
            std::cout << "[INFO] User '" << username_ << "' is disconnecting" << "\n";
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

/*
Implementations of ChatRoom member functions that require the complete ChatSession type
These are defined after the full ChatSession definition
*/
void ChatRoom::join(std::shared_ptr<ChatSession> session) {
    std::unique_lock<std::timed_mutex> lock(mtx_, std::chrono::milliseconds(100));
    if (!lock.owns_lock()) {
        std::cerr << "[ERROR] ChatRoom::join: Failed to acquire lock" << "\n";
        return;
    }
    sessions_.push_back(session);
    std::cout << "[INFO] ChatRoom: New session joined. Total sessions: " << sessions_.size() << "\n";
}

void ChatRoom::leave(std::shared_ptr<ChatSession> session) {
    std::unique_lock<std::timed_mutex> lock(mtx_, std::chrono::milliseconds(100));
    if (!lock.owns_lock()) {
        std::cerr << "[ERROR] ChatRoom::leave: Failed to acquire lock" << "\n";
        return;
    }
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
        std::unique_lock<std::timed_mutex> lock(mtx_, std::chrono::milliseconds(100));
        if (!lock.owns_lock()) {
            std::cerr << "[ERROR] ChatRoom::broadcast: Failed to acquire lock" << "\n";
            return;
        }
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (auto s = it->lock()) {
                actives.push_back(s);
                ++it;
            } else {
                it = sessions_.erase(it);
            }
        }
    }
    std::cout << "[INFO] Broadcasting message to " << actives.size() << " sessions" << "\n";
    for (auto& session : actives) {
        // Schedule the send operation with normal priority
        g_scheduler->scheduleTask(Priority::Normal, [session, message]() {
            session->send(message);
        });
    }
}

/*
HttpAuthSession handles HTTP requests to the /auth endpoint for user login and registration.
It reads the request, processes it, and writes a JSON response.
*/
class HttpAuthSession : public std::enable_shared_from_this<HttpAuthSession> {
private:
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
public:
    /*
    Constructor that initializes the session with a socket
    */
    HttpAuthSession(tcp::socket socket)
        : socket_(std::move(socket)) {}
    /*
    Starts processing the HTTP request
    */
    void run() {
        doRead();
    }
private:
    /*
    Asynchronously reads the HTTP request
    */
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
    /*
    Handles the HTTP request for /auth by processing login or registration and sends a JSON response
    */
    void handleRequest() {
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
        res->base().clear();
        res->set(http::field::server, "MessagingApp");
        res->set(http::field::content_type, "application/json");
        {
            // Set CORS headers by echoing the request's Origin header if available. Otherwise, allow all origins.
            auto it = req_.find(http::field::origin);
            if (it != req_.end()) {
                res->set(http::field::access_control_allow_origin, std::string(it->value()));
            } else {
                res->set(http::field::access_control_allow_origin, "*");
            }
            res->set(http::field::access_control_allow_methods, "POST, GET, OPTIONS");
            res->set(http::field::access_control_allow_headers, "Content-Type");
            res->set("Access-Control-Allow-Credentials", "true");
        }
    
        std::string response_body;
        if (req_.target() == "/auth") {
            if (req_.method() == http::verb::options) {
                response_body = "";
            } else if (req_.method() == http::verb::post) {
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
            response_body = "The resource was not found";
        }
    
        res->body() = response_body;
        res->prepare_payload();
    
        auto self = shared_from_this();
        http::async_write(socket_, *res,
            [this, self, res](beast::error_code ec, std::size_t) {
                try {
                    socket_.shutdown(tcp::socket::shutdown_send, ec);
                } catch (...) {
                    // Ignore shutdown errors
                }
            });
    }
};

/*
AuthListener listens on the /auth HTTP endpoint and creates an HttpAuthSession for each connection
*/
class AuthListener : public std::enable_shared_from_this<AuthListener> {
private:
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
public:
    /*
    Constructor that initializes the listener on the specified endpoint
    */
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
    /*
    Starts accepting connections on the /auth endpoint
    */
    void run() {
        doAccept();
    }
private:
    /*
    Asynchronously accepts a new connection and creates an HttpAuthSession
    */
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

/*
ChatListener listens on the WebSocket endpoint for chat and creates a ChatSession for each connection
*/
class ChatListener : public std::enable_shared_from_this<ChatListener> {
private:
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    ChatRoom& room_;
public:
    /*
    Constructor that initializes the chat listener on the specified endpoint and associates it with a ChatRoom
    */
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
    /*
    Starts accepting WebSocket chat connections
    */
    void run() {
        doAccept();
    }
private:
    /*
    Asynchronously accepts an incoming chat connection and creates a ChatSession
    */
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

/*
Main function sets up the io_context, global task scheduler, and listeners,
then launches worker threads for concurrent processing
*/
int main() {
    try {
        net::io_context ioc;
        auto work_guard = net::make_work_guard(ioc);
        
        // Initialize global priority task scheduler
        g_scheduler = std::make_shared<PriorityTaskScheduler>(ioc);
        
        ChatRoom room;
        auto authListener = std::make_shared<AuthListener>(
            ioc, tcp::endpoint(net::ip::make_address("0.0.0.0"), 8080));
        authListener->run();
        auto chatListener = std::make_shared<ChatListener>(
            ioc, tcp::endpoint(net::ip::make_address("0.0.0.0"), 12345), room);
        chatListener->run();
        std::cout << "[INFO] Auth server started on port 8080" << "\n";
        std::cout << "[INFO] Chat server started on port 12345" << "\n";
        
        std::vector<std::thread> threads;
        unsigned thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0)
            thread_count = 1;
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
