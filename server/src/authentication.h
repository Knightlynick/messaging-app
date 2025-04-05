#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <string>

// Initialize the SQLite database. Returns true on success.
bool initDatabase();

// Register a new user using a transaction.
bool registerUser(const std::string& username, const std::string& password);

// Validate login credentials.
bool loginUser(const std::string& username, const std::string& password);

// Close the database.
void closeDatabase();

#endif
