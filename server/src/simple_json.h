#ifndef SIMPLE_JSON_H
#define SIMPLE_JSON_H

#include <string>
#include <sstream>
#include <iomanip>
#include <fmt/format.h>

namespace simple_json {

// Escape special characters in a string so that it is safe for JSON.
inline std::string escape_string(const std::string& s) {
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

// Create a JSON message with type and content.
inline std::string make_message(const std::string& type, const std::string& content) {
    return fmt::format("{{\"type\":\"{}\",\"content\":\"{}\"}}", type, escape_string(content));
}

// Create a JSON chat message that includes a username.
inline std::string make_chat_message(const std::string& username, const std::string& content) {
    return fmt::format("{{\"type\":\"chat\",\"username\":\"{}\",\"content\":\"{}\"}}",
                       escape_string(username), escape_string(content));
}

// Very basic JSON parser for our limited needs.
// It extracts the "type", "username", and "content" fields from the JSON string.
inline bool parse_message(const std::string& json, std::string& type, std::string& username, std::string& content) {
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
            if (end != std::string::npos)
                username = json.substr(start, end - start);
        }
    }
    pos = json.find("\"content\":");
    if (pos != std::string::npos) {
        size_t start = json.find('"', pos + 10);
        if (start != std::string::npos) {
            start++;
            size_t end = json.find('"', start);
            if (end != std::string::npos)
                content = json.substr(start, end - start);
        }
    }
    return has_type;
}

} // namespace simple_json

#endif // SIMPLE_JSON_H
