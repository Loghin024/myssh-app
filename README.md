# myssh-app

My-SSH is a lightweight, concurrent SSH (Secure Shell) implementation built from scratch in C for educational purpose. It leverages TCP for communication, RSA for encryption, and SQLite3 for storing user data, ensuring a secure and reliable connection for remote shell access.

## Features

- **Concurrent Design:** My-SSH is designed to handle multiple connections concurrently, making it suitable for scenarios with high concurrency requirements.

- **TCP Communication:** The project utilizes the Transmission Control Protocol (TCP) for communication, ensuring reliable and ordered data delivery between the client and server.

- **RSA Encryption:** My-SSH employs RSA encryption to secure the communication channel, providing confidentiality and integrity for sensitive data exchanged during the SSH session.

- **SQLite3 Integration:** User data is stored securely using the SQLite3 database, allowing for efficient management of user credentials and authorization.

## Getting Started

### Prerequisites

Before running My-SSH, make sure you have the following prerequisites installed:

- C compiler (e.g., GCC)
- [OpenSSL](https://www.openssl.org/) library
- [SQLite3](https://www.sqlite.org/) library
