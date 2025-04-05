#include "authentication.h"
#include <sqlite3.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <fmt/format.h>

sqlite3* db = nullptr;

bool initDatabase() {
    int rc = sqlite3_open("users.db", &db);
    if (rc) {
        std::cerr << "[ERROR] Can't open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    const char* sql_create =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE, "
        "password_hash TEXT);";
    char* errMsg = nullptr;
    rc = sqlite3_exec(db, sql_create, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] SQL error: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

std::string hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

bool registerUser(const std::string& username, const std::string& password) {
    std::string hashed = hashPassword(password);
    char* errMsg = nullptr;
    // Begin transaction
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] BEGIN TRANSACTION failed: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO users (username, password_hash) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    return true;
}

bool loginUser(const std::string& username, const std::string& password) {
    std::string hashed = hashPassword(password);
    sqlite3_stmt* stmt;
    const char* sql = "SELECT password_hash FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* stored = sqlite3_column_text(stmt, 0);
        std::string storedHash = stored ? reinterpret_cast<const char*>(stored) : "";
        sqlite3_finalize(stmt);
        return (hashed == storedHash);
    }
    sqlite3_finalize(stmt);
    return false;
}

void closeDatabase() {
    if (db) sqlite3_close(db);
}
