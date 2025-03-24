#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <set>
#include <mutex>

using boost::asio::ip::tcp;

// Global container for connected clients and a mutex for thread safety.
std::set<tcp::socket*> clients;
std::mutex clients_mutex;

void handle_client(tcp::socket* sock) {
    try {
        char data[1024];
        for (;;) {
            boost::system::error_code error;
            size_t length = sock->read_some(boost::asio::buffer(data), error);
            if (error == boost::asio::error::eof) {
                // Connection closed by client.
                break;
            } else if (error) {
                throw boost::system::system_error(error);
            }
            // Broadcast the received message to all other clients.
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                for (auto client : clients) {
                    if (client != sock) {
                        boost::asio::write(*client, boost::asio::buffer(data, length));
                    }
                }
            }
        }
    } catch (std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
    // Remove client on disconnection.
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(sock);
    }
    delete sock;
}

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 12345));
        std::cout << "Server started on port 12345. Waiting for connections..." << std::endl;
        
        while (true) {
            // Allocate socket on the heap so that its lifetime extends into the thread.
            tcp::socket* socket = new tcp::socket(io_context);
            acceptor.accept(*socket);
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                clients.insert(socket);
            }
            std::cout << "New client connected." << std::endl;
            std::thread(handle_client, socket).detach();
        }
    } catch (std::exception& e) {
        std::cerr << "Server exception: " << e.what() << std::endl;
    }
    return 0;
}
