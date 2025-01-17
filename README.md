# CryptoSign

**CryptoSign** is a web application built using the Django web framework. It leverages Elliptic Curve Cryptography (ECC) to securely sign and store software, ensuring the integrity and authenticity of the software being managed.

## Features
- **Software Signing**: Uses Elliptic Curve Cryptography (ECC) to digitally sign software.
- **Secure Storage**: Stores signed software in a secure database.
- **Web Interface**: User-friendly interface for managing software and cryptographic operations.

## Technologies Used
- **Python** (Django framework) for backend development.
- **SQLite** as the database.
- **HTML/CSS** for the frontend interface.
- **Elliptic Curve Cryptography (ECC)** for digital signing.

## Prerequisites
Before you begin, ensure you have the following installed:
- Python 3.8 or later
- pip (Python package manager)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/kalkidan-hub/cyberProject.git
   cd cyberProject
   ```

2. Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Apply migrations:
   ```bash
   python manage.py migrate
   ```

5. Start the development server:
   ```bash
   python manage.py runserver
   ```

6. Access the application in your browser at `http://127.0.0.1:8000`.

## Usage
1. Navigate to the web interface.
2. Upload software files for signing.
3. View signed software and its cryptographic details.

## Project Structure
```
cyberProject/
├── cyberProject/          # Main Django project folder
├── secureSoftware/        # Application logic for software signing and storage
├── db.sqlite3             # SQLite database file
├── manage.py              # Django management script
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```

## Security
CyberProject implements **Elliptic Curve Cryptography (ECC)**, a modern and efficient cryptographic algorithm, to ensure software signatures are secure and tamper-proof.

## Contribution
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to your fork and create a pull request:
   ```bash
   git push origin feature-name
   ```

## License
This project is open-source and available under the [MIT License](LICENSE).

## Contact
For questions or suggestions, feel free to reach out:
- **GitHub**: [kalkidan-hub](https://github.com/kalkidan-hub)

---
**Disclaimer**: This project is for educational purposes and should not be used in production without proper review and testing.

