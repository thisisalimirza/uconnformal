# Medical School Formal Registration System

A web application for managing medical school formal event registrations with waitlist functionality.

## Features
- User registration and authentication
- Plus-one guest registration
- Automatic waitlist system
- Real-time availability updates
- Admin dashboard for managing registrations

## Setup
1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file with the following:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application:
```bash
flask run
```

Visit `http://localhost:5000` in your browser to access the application. 