#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <fmt/format.h>
#include <thread>
#include <vector>
#include <iostream>
#include <algorithm>
#include "authentication.h"
#include "chat.h"
#include "http_session.h"

namespace beast = boost::beast;
namespace net = boost::asio;
using tcp = net::ip::tcp;
namespace http = boost::beast::http;

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
        acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
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
    void run() {
        if (!acceptor_.is_open())
            return;
        doAccept();
    }
private:
    void doAccept() {
        acceptor_.async_accept(net::make_strand(ioc_), [self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::cout << "[INFO] Accepted connection from " << socket.remote_endpoint() << "\n";
                std::make_shared<HttpSession>(std::move(socket), self->room_)->start();
            } else {
                std::cerr << "[ERROR] Accept error: " << ec.message() << "\n";
            }
            self->doAccept();
        });
    }
};

int main() {
    try {
        if (!initDatabase()) {
            std::cerr << "[ERROR] Failed to initialize database.\n";
            return EXIT_FAILURE;
        }
        const auto address = net::ip::make_address("0.0.0.0");
        unsigned short port = 12345;
        net::io_context ioc{1};

        ChatRoom room;
        auto listener = std::make_shared<Listener>(ioc, tcp::endpoint{address, port}, room);
        listener->run();

        std::cout << "[INFO] Server started on port " << port << "\n";

        std::vector<std::thread> threads;
        auto thread_count = std::max(1u, std::thread::hardware_concurrency() - 1);
        for (unsigned i = 0; i < thread_count; ++i)
            threads.emplace_back([&ioc] { ioc.run(); });

        ioc.run();

        for (auto& t : threads)
            t.join();

        closeDatabase();
    } catch (std::exception& e) {
        std::cerr << "[ERROR] Main error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
