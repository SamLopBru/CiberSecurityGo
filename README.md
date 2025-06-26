# 🔐 Cybersecurity Project with Go

This is a terminal-based application designed for secure **patient management** in a clinical environment. Once authenticated, a physician can:

- Add new patients
- Record observations and treatments
- View and update records for patients within the same medical specialty

While the application remains simple in its interface and scope, the focus of this project lies in the **implementation of robust cybersecurity practices**, not just functionality.

---

## 🛡️ Key Security Features

This project implements several standard security mechanisms used in healthcare and other sensitive environments:

- **Two-Factor Authentication (2FA)** using Time-based One-Time Passwords (**TOTP**)  
- **Secure password handling** using the **Argon2** hashing algorithm  
- **TLS encryption** to secure communication between clients and server  
- **Encrypted database fields** for sensitive patient data  
- **Secure password generation** to avoid weak credentials

---

## 📚 Purpose

The primary goal of this project is to **explore and apply security-first design principles** in a clinical software context. Through this work, I gained practical experience in:

- Implementing cryptographic standards in Go
- Balancing usability with secure design
- Protecting sensitive health data in accordance with best practices

This project serves as a foundational exercise in building secure systems for healthcare settings.

---

## ⚙️ How to Use

To run the application:

```bash
go run main.go
