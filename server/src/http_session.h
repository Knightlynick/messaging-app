#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include "chat.h"

using tcp = boost::asio::ip::tcp;

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(tcp::socket socket, ChatRoom& room);
    void start();
    void writeResponse(boost::beast::http::response<boost::beast::http::string_body>& res);
    void writeResponse(boost::beast::http::response<boost::beast::http::empty_body>& res);
private:
    bool parseCredentials(const std::string& body, std::string& username, std::string& password);
    void handleRequest();
private:
    tcp::socket socket_;
    boost::beast::flat_buffer buffer_;
    boost::beast::http::request<boost::beast::http::string_body> req_;
    ChatRoom& room_;
};

#endif
