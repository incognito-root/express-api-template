# TypeScript Express Project Setup Script

This script automates the setup of a TypeScript-based Express project with commonly used dependencies, a predefined folder structure, and placeholder files. Save time and avoid repetitive tasks when starting new backend projects!

## Features

- **Preinstalled Dependencies**: Includes popular libraries like `express`, `dotenv`, `bcrypt`, `jsonwebtoken`, and more.
- **Preconfigured TypeScript**: Automatically generates a `tsconfig.json` with sensible defaults.
- **Folder Structure**: Creates a well-organized directory structure for controllers, routes, services, and more.
- **Placeholder Files**: Adds boilerplate code and TODOs in essential files for quick setup.

## Installation

Clone or download the repository:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   ```
## Usage
1. Run the setup script:
   ```bash
   node setup.js
   ```
2. Enter the name of your project when prompted.
3. Wait for the script to complete. It will:
    * Create a new project folder.
    * Initialize an npm project.
    * Install required dependencies.
    * Set up the folder structure and boilerplate files.
    * Configure TypeScript with a tsconfig.json.


## Folder Structure
The script generates the following structure:

```
/your-project-name
├── src/
│   ├── config/
│   ├── controllers/
│   ├── errors/
│   ├── middlewares/
│   │   ├── Auth.ts
│   │   ├── ErrorHandler.ts
│   │   ├── Multer.ts
│   │   └── Validation.ts
│   ├── routes/
│   │   └── indexRoutes.ts
│   ├── services/
│   ├── templates/
│   ├── types/
│   ├── utils/
│   │   ├── logger.ts
│   │   ├── emailTemplates.ts
│   │   ├── nodeMailerProvider.ts
│   │   ├── prismClient.ts
│   │   └── response.ts
│   ├── validations/
│   └── app.ts
├── package.json
├── tsconfig.json
└── README.md
```


## Dependencies
The script installs the following dependencies and devDependencies:

### Dependencies
  * @types/multer
  * @types/uuid
  * @types/winston
  * bcrypt
  * cookie-parser
  * cors
  * dotenv
  * express
  * express-validator
  * handlebars
  * jsonwebtoken
  * micro
  * multer
  * nodemailer
  * redis
  * uuid
  * winston
  * winston-daily-rotate-file

### Dev Dependencies
  * @prisma/client
  * @types/bcrypt
  * @types/cookie-parser
  * @types/cors
  * @types/express
  * @types/jsonwebtoken
  * @types/node
  * @types/nodemailer
  * nodemon
  * prisma
  * ts-node
  * typescript

## Configuration
  1) Add environment variables to a .env file in the project root for managing sensitive data.
  2) Update the app.ts and other placeholder files in the src/ directory as per your project's requirements.

## Author
  Developed by Your **Syed Ayaan Ali**. Contributions are welcome!
