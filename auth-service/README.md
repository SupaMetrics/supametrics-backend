# Supermetrics Auth Service:

A robust authentication service designed to manage user sign-ups, sign-ins, and OAuth processes. Built with Go, it ensures secure and efficient handling of user credentials and data encryption.

## Installation

Get started with the Supermetrics Auth Service in just a few steps!

- **Clone the Repository**:
  ```bash
  git clone https://github.com/SupaMetrics/supametrics-backend.git
  ```

- **Navigate to the Directory**:
  ```bash
  cd auth-service
  ```

- **Install Dependencies**:
  ```bash
  go mod download
  ```

- **Configure Environment Variables**:
  - Create a `.env` file in the root directory.
  - Add the `RAND_IV` variable with a 32-byte encryption key. Example:
    ```
    RAND_IV=your32byteencryptionkeyhere
    ```

- **Run the Application**:
  ```bash
  go run main.go
  ```

## Usage

Once the application is running, you can interact with the following endpoints:

- `POST /auth/signup`: Register a new user.
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword",
    "fullName": "John Doe"
  }
  ```

- `POST /auth/signin`: Authenticate an existing user.
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword"
  }
  ```

- `POST /auth/oauth`: Handle OAuth authentication.
  ```json
  {
    "email": "user@example.com",
    "fullName": "John Doe"
  }
  ```

## ✨ Features

- **User Sign-Up**: Securely register new users with email, password, and full name.
- **User Sign-In**: Authenticate existing users and grant access.
- **OAuth Support**: Streamline user access through OAuth.
- **Data Encryption**: Protect user data with AES encryption using a random IV.
- **Password Hashing**: Enhance security with bcrypt password hashing.

## Technologies Used

| Technology      | Link                                  |
| :---------------- | :------------------------------------ |
| Go              | [https://go.dev/](https://go.dev/)   |
| Gin Gonic       | [https://gin-gonic.com/](https://gin-gonic.com/) |
| bcrypt          | [https://pkg.go.dev/golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) |
| godotenv        | [https://github.com/joho/godotenv](https://github.com/joho/godotenv) |

## Contributing

We welcome contributions to enhance the Supermetrics Auth Service!

- **Report Issues**: Help us identify and fix bugs.
- **Suggest Features**: Propose new functionalities to improve the service.
- **Submit Pull Requests**: Contribute code enhancements.

Please follow these guidelines:

- Use clear and concise commit messages.
- Write tests for new features.
- Update documentation accordingly.

## License

This project is licensed under the [MIT License](LICENSE).

[![Readme was generated by Dokugen](https://img.shields.io/badge/Readme%20was%20generated%20by-Dokugen-brightgreen)](https://www.npmjs.com/package/dokugen)
