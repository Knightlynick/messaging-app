#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/format.hpp>
#include <fmt/core.h>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <future>        // For std::async
#include <atomic>        // For std::atomic
#include <condition_variable> // For condition variables

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

// This holds a list of all connected WebSocket sessions
class shared_state {
private:
    std::vector<std::shared_ptr<websocket::stream<beast::tcp_stream>>> sessions_;
    std::mutex mutex_;
    std::vector<std::string> message_history_;
    const size_t max_history_size_ = 100;
    
    // Task queue for background processing
    struct Task {
        std::function<void()> task;
        bool is_high_priority;
    };
    std::vector<Task> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::atomic<bool> stop_workers_{false};
    std::vector<std::thread> worker_threads_;

public:
    shared_state(size_t num_workers = 2) {
        // Start worker threads for background processing
        startWorkerThreads(num_workers);
    }
    
    ~shared_state() {
        // Signal worker threads to stop and join them
        stopWorkerThreads();
    }
    
    void join(std::shared_ptr<websocket::stream<beast::tcp_stream>> ws) {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.push_back(ws);
        std::cout << "Client joined. Total clients: " << sessions_.size() << std::endl;
        
        // Send a notification to all clients about the new join
        std::string join_message = "System: A new client has joined the chat.";
        enqueueTask([this, join_message]() {
            this->broadcast(join_message);
        }, true);
    }
    
    void leave(std::shared_ptr<websocket::stream<beast::tcp_stream>> ws) {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.erase(
            std::remove(sessions_.begin(), sessions_.end(), ws),
            sessions_.end());
        std::cout << "Client left. Total clients: " << sessions_.size() << std::endl;
        
        // Send a notification about the client leaving
        std::string leave_message = "System: A client has left the chat.";
        enqueueTask([this, leave_message]() {
            this->broadcast(leave_message);
        }, true);
    }
    
    void broadcast(std::string message) {
        // Save message in history
        {
            std::lock_guard<std::mutex> lock(mutex_);
            message_history_.push_back(message);
            if (message_history_.size() > max_history_size_)
                message_history_.erase(message_history_.begin());
        }
        std::cout << "Broadcasting message: " << message << std::endl;
        
        // Format as a JSON message for Socket.io compatibility
        std::string json_message = fmt::format("42[\"receive_message\",\"{}\"]", message);
        std::vector<std::shared_ptr<websocket::stream<beast::tcp_stream>>> active_sessions;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Create a copy of sessions to work with outside the lock
            active_sessions = sessions_;
        }
        
        for (auto session : active_sessions) {
            // Ensure session is valid and open
            if (session && session->is_open()) {
                try {
                    beast::flat_buffer buffer;
                    session->write(net::buffer(json_message));
                } catch (std::exception& e) {
                    std::cerr << "Error broadcasting message: " << e.what() << std::endl;
                }
            }
        }
    }
    
    void send_history(std::shared_ptr<websocket::stream<beast::tcp_stream>> ws) {
        std::vector<std::string> history;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            history = message_history_;
        }
        
        // Send each message in the history to the new client
        for (const auto& msg : history) {
            if (ws && ws->is_open()) {
                try {
                    std::string json_message = fmt::format("42[\"receive_message\",\"{}\"]", msg);
                    ws->write(net::buffer(json_message));
                } catch (std::exception& e) {
                    std::cerr << "Error sending history: " << e.what() << std::endl;
                }
            }
        }
    }
    
    std::vector<std::string> get_history() {
        std::lock_guard<std::mutex> lock(mutex_);
        return message_history_;
    }

private:
    void startWorkerThreads(size_t num_workers) {
        for (size_t i = 0; i < num_workers; ++i) {
            worker_threads_.emplace_back([this]() {
                workerFunction();
            });
        }
    }
    
    void stopWorkerThreads() {
        stop_workers_ = true;
        queue_condition_.notify_all();
        
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        worker_threads_.clear();
    }
    
    void workerFunction() {
        while (!stop_workers_) {
            Task task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_condition_.wait(lock, [this]() {
                    return !task_queue_.empty() || stop_workers_;
                });
                
                if (stop_workers_ && task_queue_.empty()) {
                    return;
                }
                
                // Find the highest priority task
                auto it = std::find_if(task_queue_.begin(), task_queue_.end(),
                    [](const Task& t) { return t.is_high_priority; });
                    
                if (it != task_queue_.end()) {
                    task = std::move(*it);
                    task_queue_.erase(it);
                } else if (!task_queue_.empty()) {
                    task = std::move(task_queue_.front());
                    task_queue_.erase(task_queue_.begin());
                } else {
                    continue;
                }
            }
            
            // Execute the task outside the lock
            try {
                task.task();
            } catch (const std::exception& e) {
                std::cerr << "Task execution error: " << e.what() << std::endl;
            }
        }
    }

public:
    void enqueueTask(std::function<void()> task, bool is_high_priority = false) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            task_queue_.push_back({std::move(task), is_high_priority});
        }
        queue_condition_.notify_one();
    }
};

// This handles one WebSocket connection
class session : public std::enable_shared_from_this<session> {
    std::shared_ptr<websocket::stream<beast::tcp_stream>> ws_;
    beast::flat_buffer buffer_;
    std::shared_ptr<shared_state> state_;
    std::string sender_id_;

public:
    // Take ownership of the socket and HTTP request
    session(tcp::socket&& socket, std::shared_ptr<shared_state> state, 
            http::request<http::string_body>&& req)
        : ws_(std::make_shared<websocket::stream<beast::tcp_stream>>(std::move(socket)))
        , state_(state) {
        // Generate a simple ID for this session
        sender_id_ = "user_" + std::to_string(rand() % 10000);
        
        // Set suggested timeout settings for the websocket
        ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        // Set a decorator to allow the client to connect from any origin
        ws_->set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server, "Boost.Beast WebSocket Server");
                res.set(http::field::access_control_allow_origin, "*");
            }));
        
        // Accept the websocket handshake
        ws_->accept(req);
    }

    void start() {
        // Add this session to the shared state
        state_->join(ws_);

        // Send message history to the new client
        (void)std::async(std::launch::async, [self = shared_from_this()]() {
            self->state_->send_history(self->ws_);
        });

        // Send a welcome message
        try {
            std::string welcome = "System: Welcome to the chat room, " + sender_id_ + "!";
            state_->broadcast(welcome);

            // Start reading messages
            do_read();
        } 
        catch (std::exception& e) {
            std::cerr << "Error in start: " << e.what() << std::endl;
        }
    }

private:
    void do_read() {
        // Read a message
        ws_->async_read(
            buffer_,
            [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
                self->on_read(ec, bytes_transferred);
            });
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        // This indicates a graceful closure
        if (ec == websocket::error::closed) {
            state_->leave(ws_);
            return;
        }
        
        if (ec) {
            std::cerr << "Read error: " << ec.message() << std::endl;
            state_->leave(ws_);
            return;
        }
        
        // Extract the message
        std::string message = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());
        std::cout << "Received raw message: " << message << std::endl;
        
        // Process the message asynchronously
        state_->enqueueTask([self = shared_from_this(), message]() {
            self->process_message(message);
        });
        
        // Read another message
        do_read();
    }
    
    void process_message(const std::string& message) {
        // Parse Socket.io message format
        if (message.substr(0, 2) == "42") {
            try {
                // Very basic parsing of Socket.io message format
                // Format is usually: 42["event_name","message_content"]
                size_t start = message.find("[\"send_message\",\"");
                if (start != std::string::npos) {
                    start += 16; // Length of ["send_message","
                    size_t end = message.find("\"]", start);
                    if (end != std::string::npos) {
                        std::string extracted_message = message.substr(start, end - start);
                        
                        // Create a formatted message with sender ID
                        std::string formatted_message = sender_id_ + ": " + extracted_message;
                        
                        // Broadcast the message to all connected clients
                        state_->broadcast(formatted_message);
                    }
                }
            } catch (std::exception& e) {
                std::cerr << "Error parsing message: " << e.what() << std::endl;
            }
        } else {
            // For non-Socket.io format, just echo it back
            try {
                std::string formatted_message = sender_id_ + " (raw): " + message;
                state_->broadcast(formatted_message);
            } catch (std::exception& e) {
                std::cerr << "Error broadcasting raw message: " << e.what() << std::endl;
            }
        }
    }
};

// Handle an HTTP request
class http_session : public std::enable_shared_from_this<http_session> {
    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<shared_state> state_;

public:
    http_session(tcp::socket&& socket, std::shared_ptr<shared_state> state)
        : stream_(std::move(socket))
        , state_(state) {
    }

    void start() {
        // Read the HTTP request
        http::async_read(stream_, buffer_, req_,
            [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(bytes_transferred);
                if (!ec)
                    self->on_read();
            });
    }

private:
    void on_read() {
        // See if it's a WebSocket upgrade
        if (websocket::is_upgrade(req_)) {
            std::cout << "WebSocket upgrade request received." << std::endl;
            try {
                // Create a websocket session and transfer ownership of the socket
                std::make_shared<session>(
                    stream_.release_socket(),
                    state_,
                    std::move(req_))->start();
                std::cout << "WebSocket session successfully created." << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error during WebSocket session creation: " << e.what() << std::endl;
            }
            return;
        }

        // It's not a WebSocket upgrade, send a simple response
        std::cout << "Received non-WebSocket request." << std::endl;
        auto response = std::make_shared<http::response<http::string_body>>(
            http::status::ok, req_.version());
        response->set(http::field::server, "Beast");
        response->set(http::field::content_type, "text/html");
        response->keep_alive(req_.keep_alive());
        response->body() = "WebSocket server is running. Please use a WebSocket client to connect.";
        response->prepare_payload();

        // Send the response
        http::async_write(stream_, *response,
            [self = shared_from_this(), response](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(bytes_transferred);
                if (ec) {
                    std::cerr << "Error sending HTTP response: " << ec.message() << std::endl;
                } else {
                    std::cout << "HTTP response sent successfully." << std::endl;
                }
                self->stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
            });
    }
};

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener> {
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<shared_state> state_;

public:
    listener(
        net::io_context& ioc,
        tcp::endpoint endpoint,
        std::shared_ptr<shared_state> state)
        : ioc_(ioc)
        , acceptor_(ioc)
        , state_(state) {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if (ec) {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void run() {
        do_accept();
    }

private:
    void do_accept() {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            [self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::cout << "Accepted a new connection from: " << socket.remote_endpoint().address().to_string() << std::endl;
                } else {
                    std::cerr << "Error accepting connection: " << ec.message() << std::endl;
                }
                self->on_accept(ec, std::move(socket));
            });
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            fail(ec, "accept");
        } else {
            // Create the HTTP session and run it
            std::make_shared<http_session>(
                std::move(socket),
                state_)->start();
        }

        // Accept another connection
        do_accept();
    }

    void fail(beast::error_code ec, char const* what) {
        std::cerr << what << ": " << ec.message() << std::endl;
    }
};

int main(int argc, char* argv[]) {
    try {
        // Check command line arguments.
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " <address> <port>\n";
            std::cerr << "Example:\n";
            std::cerr << "    " << argv[0] << " 0.0.0.0 12345\n";
            return EXIT_FAILURE;
        }
        auto const address = net::ip::make_address(argv[1]);
        auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
        
        // The number of threads to use for the server
        const int num_threads = std::max(4u, std::thread::hardware_concurrency());
        std::cout << "Server starting with " << num_threads << " threads." << std::endl;
        
        // The io_context is required for all I/O
        net::io_context ioc{num_threads};
        
        // Create the shared state with worker threads for background processing
        auto state = std::make_shared<shared_state>(2); // 2 worker threads
        
        // Create and launch a listening port
        std::make_shared<listener>(
            ioc,
            tcp::endpoint{address, port},
            state)->run();
            
        // Create a vector of threads for running the io_context
        std::vector<std::thread> threads;
        threads.reserve(num_threads - 1); // Reserve one less because we'll use the main thread too
        
        // Launch (num_threads - 1) threads
        for (auto i = num_threads - 1; i > 0; --i) {
            threads.emplace_back([&ioc] {
                ioc.run();
            });
        }
        
        std::cout << "WebSocket server listening on " << address << ":" << port << std::endl;
        
        // Run the I/O service on the main thread as well
        ioc.run();
        
        // Wait for all threads to exit
        for (auto& t : threads) {
            t.join();
        }
        
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
