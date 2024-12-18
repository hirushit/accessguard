# **AccessGuard: Secure RBAC System**

AccessGuard is a comprehensive **Role-Based Access Control (RBAC)** system designed to secure and manage user access across multiple roles within an application. With an intuitive interface and robust authentication mechanisms, AccessGuard allows administrators, moderators, and users to interact with content securely.

This project uses **JWT-based authentication**, with access tokens that are valid for 1 hour. It offers a secure way to handle user roles and permissions, as well as features like OTP-based password recovery and email notifications for new logins.

## **Tech Stack**

-   **Backend**: Node.js, Express.js
-   **Authentication**: JWT (JSON Web Tokens)
-   **Password Hashing**: Argon2 (for secure password hashing)
-   **Database**: MongoDB (hosted on **MongoDB Atlas** with Mongoose ORM)
-   **Email Service**: Nodemailer (for sending OTPs and notifications)
-   **Frontend**: EJS templating engine
-   **Styling**: Bootstrap
-   **Other Libraries**: Argon2 (for hashing passwords), Crypto (for OTP generation)

## **Project Overview**

AccessGuard enables a secure RBAC system that ensures only authorized users can access specific resources based on their roles. The system allows users, moderators, and admins to perform actions specific to their permissions. It also supports easy password recovery using email-based OTPs.

## **Key Features**

### **User Roles and Permissions**

1.  **User Role:**
    
    -   Default role for all newly registered users.
    -   **Can**:
        -   View existing news posts
        -   Post new news (if permission granted)
        -   Update their profile and change password
        -   Receive login alerts when logging in from a new device or IP
2.  **Moderator Role:**
    
    -   **Can**:
        -   Add news posts with **priority (High, Medium, Low)**
        - Update the priority of other posts (Change priority between High, Medium, and Low)
        -   Edit their own profile and change password
        -   View all user profiles
        -   Mark news posts with a verified symbol
        -   Report existing news posts with a reason
3.  **Admin Role:**
    
    -   **Can**:
        -   Create, edit, and delete users with specific roles (User, Moderator, Admin)
        -   Create and delete news posts
        -   View and manage reported posts from moderators
        -   Promote/demote users (User ↔ Moderator)
        -   Edit news post priority and manage posts
        -   Manage user roles (promote/demote from User to Moderator and vice versa)
        -   Admin can manage users' ability to post and view news

### **Authentication and Security**

-   **JWT-based Authentication**:
    
    -   Secure login and token-based authentication using JWT.
    -   **Access tokens** expire every 1 hour for security.
-   **Password Recovery**:
    
    -   Users can reset their password by receiving a **One-Time Password (OTP)** on their registered email.
    -   The OTP expires after 1 hour to maintain security.
-   **Password Hashing with Argon2**:
    
    -   Passwords are securely hashed using **Argon2**, a modern and highly secure password hashing algorithm that offers robust protection against brute-force and rainbow table attacks. Argon2 is particularly resistant to GPU-based attacks, ensuring that passwords remain secure even in the face of powerful hardware-based attacks.    
    -   Unlike older algorithms like **MD5** or **SHA-1**, which have known vulnerabilities and are prone to attacks, Argon2 is specifically designed to be resistant to such risks. It is also more secure than **bcrypt** due to its higher resistance to parallel processing, making it a superior choice for securing passwords.
-   **Email Alerts**:
    
    -   Users receive email notifications when they log in from a new browser or IP address.

## **Routes and Response Type**

This project uses **EJS** templates for rendering views, demonstrating the backend response rendered on the server side. Normally, a JSON response is used to connect with front-end frameworks (like React or Angular), but in this project, EJS templates are used to show the results directly in the browser.

## **Deployment**

The project is deployed and available for public access at:

[AccessGuard Deployment](https://accessguard-50023726343.development.catalystappsail.in/)

> **Note**: The application is deployed using **Zoho Catalyst AppSail**.


## **Sample Login for Each Role**

Here are sample login details for different roles to access the application:

### **1. User Login**

-   **Email**: `hirushit@gmail.com`
-   **Password**: `Password@user`

### **2. Moderator Login**

-   **Email**: `hirushit8@gmail.com`
-   **Password**: `Password@mod`

### **3. Admin Login**

-   **Email**: `hirushit@myyahoo.com`
-   **Password**: `Passoword@admin`

Here’s the updated **Installation and Setup** section with the mention of the `.env.example` file containing all required credentials:


Here's the updated **Installation and Setup** section with the Node.js version requirement:

## **Installation and Setup**

To set up the project locally, follow these steps:

1.  **Prerequisites**:
    
    -   Ensure that **Node.js** is installed on your system.
        -   This project was built and tested using **Node.js v20**.
        -   You can download the latest version of Node.js from [Node.js Official Website](https://nodejs.org/).
2.  **Clone the Repository**:
    
    ```bash
    git clone https://github.com/hirushit/accessguard.git
    cd accessguard
    ```
    
3.  **Install Dependencies**:
    
    ```bash
    npm install
    ```
    
4.  **Environment Variables**:
    
    -   Create a `.env` file in the project root directory.
        
    -   A `.env.example` file is included in the repository, containing all the necessary credentials and configuration details. You can copy its content to your `.env` file and update the values as needed.
        
        ```bash
        cp .env.example .env
        ```
        
5.  **Run the Server**:
    
    ```bash
    npm start
    ```
    
6.  **Access the Application**:  
    Open your browser and navigate to `http://localhost:3000`.
    

----------
