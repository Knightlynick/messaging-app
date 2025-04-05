#include "http_session.h"
#include "authentication.h"
#include "chat.h"
#include <boost/beast/http.hpp>
#include <iostream>

namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

// Constructor: initializes with a moved socket and a reference to the chat room.
HttpSession::HttpSession(tcp::socket socket, ChatRoom& room)
    : socket_(std::move(socket)), room_(room) {}

// Start reading the HTTP request.
void HttpSession::start() {
    auto self = shared_from_this();
    http::async_read(socket_, buffer_, req_,
        [self](boost::beast::error_code ec, std::size_t bytes_transferred) {
            boost::ignore_unused(bytes_transferred);
            if (!ec)
                self->handleRequest();
            else
                std::cerr << "[ERROR] HTTP read error: " << ec.message() << "\n";
        });
}

bool HttpSession::parseCredentials(const std::string& body, std::string& username, std::string& password) {
    auto pos = body.find("\"username\"");
    if (pos == std::string::npos) return false;
    pos = body.find(":", pos);
    if (pos == std::string::npos) return false;
    pos = body.find("\"", pos);
    if (pos == std::string::npos) return false;
    size_t start = pos + 1;
    size_t end = body.find("\"", start);
    if (end == std::string::npos) return false;
    username = body.substr(start, end - start);

    pos = body.find("\"password\"");
    if (pos == std::string::npos) return false;
    pos = body.find(":", pos);
    if (pos == std::string::npos) return false;
    pos = body.find("\"", pos);
    if (pos == std::string::npos) return false;
    start = pos + 1;
    end = body.find("\"", start);
    if (end == std::string::npos) return false;
    password = body.substr(start, end - start);
    return true;
}

void HttpSession::handleRequest() {
    // Handle preflight OPTIONS request.
    if (req_.method() == http::verb::options) {
        http::response<http::empty_body> res{http::status::ok, req_.version()};
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        res.prepare_payload();
        writeResponse(res);
        return;
    }

    // If this is a WebSocket upgrade request, delegate to ChatSession.
    if (boost::beast::websocket::is_upgrade(req_)) {
        std::make_shared<ChatSession>(std::move(socket_), room_)->start();
        return;
    }

    // Handle HTTP POST endpoints.
    if (req_.method() == http::verb::post) {
        std::string target = std::string(req_.target());
        std::string body = req_.body();
        std::string username, password;
        bool parsed = parseCredentials(body, username, password);
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "application/json");
        // Add CORS headers.
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");

        if (!parsed) {
            res.body() = "{\"status\":\"error\",\"message\":\"Invalid request format\"}";
            res.prepare_payload();
            writeResponse(res);
            return;
        }
        if (target == "/register") {
            if (registerUser(username, password)) {
                res.result(http::status::ok);
                res.body() = "{\"status\":\"success\",\"message\":\"User registered successfully\"}";
            } else {
                res.result(http::status::bad_request);
                res.body() = "{\"status\":\"error\",\"message\":\"Registration failed (user may already exist)\"}";
            }
        } else if (target == "/login") {
            if (loginUser(username, password)) {
                res.result(http::status::ok);
                res.body() = "{\"status\":\"success\",\"message\":\"Login successful\"}";
            } else {
                res.result(http::status::unauthorized);
                res.body() = "{\"status\":\"error\",\"message\":\"Invalid username or password\"}";
            }
        } else {
            res.result(http::status::not_found);
            res.body() = "{\"status\":\"error\",\"message\":\"Endpoint not found\"}";
        }
        res.prepare_payload();
        writeResponse(res);
    } else {
        http::response<http::string_body> res{http::status::not_found, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        res.body() = "{\"status\":\"error\",\"message\":\"Not found\"}";
        res.prepare_payload();
        writeResponse(res);
    }
}

// Explicit overload for responses with string_body.
void HttpSession::writeResponse(http::response<http::string_body>& res) {
    // Make a local copy instead of moving.
    http::response<http::string_body> local_res = res;
    auto response_ptr = std::make_shared<http::response<http::string_body>>(local_res);
    auto self = shared_from_this();
    http::async_write(socket_, *response_ptr,
        [self, response_ptr](boost::beast::error_code ec, std::size_t) {
            self->socket_.shutdown(tcp::socket::shutdown_send, ec);
        });
}


// Explicit overload for responses with empty_body.
void HttpSession::writeResponse(http::response<http::empty_body>& res) {
    auto response_ptr = std::make_shared<http::response<http::empty_body>>(res);
    auto self = shared_from_this();
    http::async_write(socket_, *response_ptr,
        [self, response_ptr](boost::beast::error_code ec, std::size_t /*bytes_transferred*/) {
            self->socket_.shutdown(tcp::socket::shutdown_send, ec);
        });
}
