const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question("Enter the name of your TypeScript project: ", (projectName) => {
  try {
    console.log("Setting up your TypeScript Express project...");

    // Step 1: Create the project folder
    execSync(`mkdir ${projectName}`);
    const projectPath = path.join(process.cwd(), projectName);
    process.chdir(projectPath);

    // Step 2: Initialize the project with npm
    execSync("npm init -y", { stdio: "inherit" });

    // Step 3: Install dependencies and devDependencies
    console.log("Installing dependencies...");
    const dependencies = [
      "@types/multer",
      "@types/uuid",
      "@types/winston",
      "bcrypt",
      "cookie-parser",
      "cors",
      "dotenv",
      "express",
      "express-validator",
      "handlebars",
      "jsonwebtoken",
      "micro",
      "multer",
      "nodemailer",
      "redis",
      "uuid",
      "winston",
      "winston-daily-rotate-file",
    ];
    execSync(`npm install ${dependencies.join(" ")}`, { stdio: "inherit" });

    console.log("Installing devDependencies...");
    const devDependencies = [
      "@prisma/client",
      "@types/bcrypt",
      "@types/cookie-parser",
      "@types/cors",
      "@types/express",
      "@types/jsonwebtoken",
      "@types/node",
      "@types/nodemailer",
      "nodemon",
      "prisma",
      "ts-node",
      "typescript",
    ];
    execSync(`npm install -D ${devDependencies.join(" ")}`, {
      stdio: "inherit",
    });

    // Step 4: Create folder structure
    console.log("Creating folder structure...");
    const folders = [
      "src/config",
      "src/controllers",
      "src/errors",
      "src/middlewares",
      "src/routes",
      "src/services",
      "src/templates",
      "src/types",
      "src/utils",
      "src/validations",
    ];
    folders.forEach((folder) => fs.mkdirSync(folder, { recursive: true }));

    // Step 5: Create files with placeholders
    console.log("Creating files...");
    const files = [
      {
        folder: "src/middlewares",
        files: ["Auth.ts", "ErrorHandler.ts", "Multer.ts", "Validation.ts"],
      },
      {
        folder: "src/utils",
        files: [
          "logger.ts",
          "emailTemplate.ts",
          "nodeMailerProvider.ts",
          "prismaClient.ts",
          "response.ts",
        ],
      },
      { folder: "src/routes", files: ["indexRoutes.ts"] },
      { folder: "src", files: ["app.ts"] },
    ];

    files.forEach(({ folder, files }) =>
      files.forEach((file) =>
        fs.writeFileSync(
          path.join(projectPath, folder, file),
          "// TODO: Add content here\n",
          "utf8"
        )
      )
    );

    /* index route content */
    const indexRoutesContent = `import express from "express";

    const router = express.Router();

    export default router;
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/routes/indexRoutes.ts"),
      indexRoutesContent,
      "utf8"
    );

    /* App Error content */
    const appErrorContent = `
    export class AppError extends Error {
            public readonly statusCode: number;
            public readonly isOperational: boolean;

            constructor(message: string, statusCode: number, isOperational = true) {
            super(message);
            this.statusCode = statusCode;
            this.isOperational = isOperational;

            Error.captureStackTrace(this, this.constructor);
        }
    }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/AppError.ts"),
      appErrorContent,
      "utf8"
    );

    /* bad request error content */
    const badRequestErrorContent = `
        import { AppError } from "./AppError";

        interface FormattedError {
            field: string;
            message: string;
        }

        export class BadRequestError extends AppError {
        errors?: FormattedError[];

            constructor(message: string, errors?: FormattedError[]) {
                super(message, 400);
                this.name = "BadRequestError";
                if (errors) {
                this.errors = errors;
                }
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/BadRequestError.ts"),
      badRequestErrorContent,
      "utf8"
    );

    /* conflict error content */
    const conflictErrorContent = `
        import { AppError } from "./AppError";

        export class ConflictError extends AppError {
            constructor(message: string = "Conflict") {
                super(message, 409);
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/ConflictError.ts"),
      conflictErrorContent,
      "utf8"
    );

    /* forbidden error content */
    const forbiddenErrorContent = `
        import { AppError } from "./AppError";

        export class ForbiddenError extends AppError {
            constructor(message: string = "Forbidden") {
                super(message, 403);
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/ForbiddenError.ts"),
      forbiddenErrorContent,
      "utf8"
    );

    /* internal server error content */
    const internalServerErrorContent = `
        import { AppError } from "./AppError";

        export class InternalServerError extends AppError {
            constructor(message: string = "Internal Server Error") {
                super(message, 500);
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/InternalServerError.ts"),
      internalServerErrorContent,
      "utf8"
    );

    /* invalid credentials error content */
    const invalidCredsErrorContent = `
        import { AppError } from "./AppError";

        export class InvalidCredentialsError extends AppError {
            constructor(message: string = "Invalid credentials") {
                super(message, 401);
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/InvalidCredentialsError.ts"),
      invalidCredsErrorContent,
      "utf8"
    );

    /* not found error content */
    const notFoundErrorContent = `
        import { AppError } from "./AppError";

        export class NotFoundError extends AppError {
            constructor(message: string = "Resource not found") {
                super(message, 404);
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/NotFoundError.ts"),
      notFoundErrorContent,
      "utf8"
    );

    /* unauthorized error content */
    const unauthorizedErrorContent = `
        import { AppError } from "./AppError";

        export class UnauthorizedError extends AppError {
            constructor(message: string = "Unauthorized") {
                super(message, 401);
            }
        }
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/errors/UnauthorizedError.ts"),
      unauthorizedErrorContent,
      "utf8"
    );

    /* Auth middleware content */
    const authMiddlewareContent = `
    import { Request, Response, NextFunction } from "express";
    import * as authService from "../services/authService";
    import { UnauthorizedError } from "../errors/UnauthorizedError";
    import { ForbiddenError } from "../errors/ForbiddenError";
    import { timeInMs } from "../types/timeInMS";

    interface UserPayload {
    id: number;
    email: string;
    type: string;
    userType: string;
    role?: string;
    }

    export interface RequestWithUser extends Request {
    user?: UserPayload;
    }

    export const verifyToken = async (
    req: RequestWithUser,
    res: Response,
    next: NextFunction
    ) => {
    const token = req.cookies.accessToken;
    const refreshToken = req.cookies.refreshToken;

    if (!token && !refreshToken) {
        next(new UnauthorizedError("Access denied. No token provided."));
        return;
    } else {
        try {
        const decoded = (await authService.validateToken(
            token,
            "ACCESS"
        )) as UserPayload;

        req.user = decoded;
        next();
        } catch (error) {
        if (!refreshToken) {
            next(new UnauthorizedError("Invalid or expired token."));
        }

        try {
            const result = await authService.refreshAccessToken(refreshToken);

            if (result.accessToken) {
            res.cookie("accessToken", result.accessToken, {
                maxAge: timeInMs.hour,
                httpOnly: process.env.NODE_ENV === "production",
                secure: process.env.NODE_ENV === "production",
            });

            const decoded = (await authService.validateToken(
                result.accessToken,
                "ACCESS"
            )) as UserPayload;

            req.user = decoded;
            next();
            } else {
            throw new UnauthorizedError();
            }
        } catch (error) {
            next(new UnauthorizedError("Invalid refresh token."));
        }
        }
    }
    };

    export const authorizeRoles = (...userTypes: string[]) => {
    return (req: RequestWithUser, res: Response, next: NextFunction): void => {
        if (!req.user || !userTypes.includes(req.user.role!)) {
        next(new ForbiddenError("Access denied."));
        return;
        }
        next();
    };
    };

    export const authorizeUserType = (...userTypes: string[]) => {
    return (req: RequestWithUser, res: Response, next: NextFunction): void => {
        if (!req.user || !userTypes.includes(req.user.userType!)) {
        next(new ForbiddenError("Access denied."));
        return;
        }
        next();
    };
    };

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/middlewares/Auth.ts"),
      authMiddlewareContent,
      "utf8"
    );

    /* error handler middlware content */
    const errorHandlerContent = `
    import { Request, Response, NextFunction } from "express";
    import logger from "../utils/logger";
    import { AppError } from "../errors/AppError";
    import { BadRequestError } from "../errors/BadRequestError";

    const errorHandler = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
    ) => {
    if (res.headersSent) {
        return next(err);
    }

    const isDevelopment = process.env.NODE_ENV === "development";
    const isOperationalError = err instanceof AppError;
    const isBadRequestError = err instanceof BadRequestError;

    let statusCode = isOperationalError ? (err as AppError).statusCode : 500;
    if (isBadRequestError) statusCode = 400;

    let logLevel: "error" | "warn" = statusCode >= 500 ? "error" : "warn";
    let message = isOperationalError ? err.message : "Internal Server Error";

    let stack = isDevelopment ? err.stack : undefined;

    const logMeta = {
        statusCode,
        stack,
        error: {
        name: err.name,
        message: err.message,
        stack: err.stack,
        },
        request: {
        url: req.originalUrl,
        method: req.method,
        headers: isDevelopment ? req.headers : undefined,
        ip: req.ip,
        userId: (req as any).user?.id,
        requestId: (req as any).id,
        body: req.body,
        query: req.query,
        params: req.params,
        },
        timestamp: new Date().toISOString(),
    };

    if (isDevelopment) {
        console.group("🚨 Error Details");
        console.error("Error Message:", err.message);
        console.error("Error Name:", err.name);
        console.error("Error Stack:", err.stack);
        console.group("Request Details");
        console.log("URL:", req.originalUrl);
        console.log("Method:", req.method);
        console.log("Body:", req.body);
        console.log("Query:", req.query);
        console.log("Params:", req.params);
        console.log("Headers:", req.headers);
        console.groupEnd();
        console.groupEnd();
    }

    // Enhanced logging with more context in development
    logger[logLevel](
        isDevelopment ? \`[\${err.name}] \${message}\` : message,
        isDevelopment
        ? logMeta
        : { ...logMeta, request: { ...logMeta.request, headers: undefined } }
    );

    const response: {
        status: string;
        message: string;
        stack?: string;
        requestId?: string;
        errorName?: string;
        errorDetails?: any;
        details?: Array<{ field: string; message: string }>;
    } = {
        status: "error",
        message: isOperationalError ? message : "Internal Server Error",
    };

    if (isBadRequestError && (err as BadRequestError).errors) {
        response.details = (err as BadRequestError).errors;
    }

    if (isDevelopment) {
        response.stack = stack;
        response.requestId = (req as any).id;
        response.errorName = err.name;
        response.errorDetails = {
        name: err.name,
        message: err.message,
        stack: err.stack,
        isOperational: isOperationalError,
        isBadRequest: isBadRequestError,
        };
    }

    res.status(statusCode).json(response);
    };

    export default errorHandler;
`;

    fs.writeFileSync(
      path.join(projectPath, "src/middlewares/ErrorHandler.ts"),
      errorHandlerContent,
      "utf8"
    );

    /* multer middleware content */
    const multerMiddlewareContent = `
        import multer, { FileFilterCallback, Multer } from "multer";
import { Request } from "express";
import path from "path";

const fileFilter =
  (allowedTypes: string[]) =>
  (req: Request, file: Express.Multer.File, cb: FileFilterCallback) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(\`Only \${allowedTypes.join(", ")} files are allowed!\`));
    }
  };

class UploadMiddleware {
  private multerInstance: Multer;

  constructor(private allowedTypes: { [key: string]: string[] }) {
    this.multerInstance = multer({
      storage: multer.memoryStorage(),
      fileFilter: this.dynamicFileFilter.bind(this),
    });
  }

  private dynamicFileFilter(
    req: Request,
    file: Express.Multer.File,
    cb: FileFilterCallback
  ) {
    const routePath = req.route.path;
    const allowedTypesForRoute = this.allowedTypes[routePath] || [];
    fileFilter(allowedTypesForRoute)(req, file, cb);
  }

  single(fieldName: string) {
    return this.multerInstance.single(fieldName);
  }

  // You can add other multer methods here as needed
}

export const upload = new UploadMiddleware({
  "/lawyerDocument": [".pdf"],
  "/profilePicture": [".jpg", ".jpeg", ".png"],
  "/conversation": [
    ".jpg",
    ".jpeg",
    ".png",
    ".pdf",
    ".doc",
    ".docx",
    ".txt",
    ".ppt",
    ".pptx",
  ],
  // Add more routes and their allowed file types as needed
});

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/middlewares/Multer.ts"),
      multerMiddlewareContent,
      "utf8"
    );

    /* validation middleware content */
    const validationMiddlewareContent = `
        import { Request, Response, NextFunction } from "express";
import {
  ValidationError,
  validationResult,
  FieldValidationError,
} from "express-validator";
import { BadRequestError } from "../errors/BadRequestError"; // Update the path accordingly

interface FormattedError {
  field: string;
  message: string;
}

export const handleValidationErrors = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const formattedErrors: FormattedError[] = errors
      .array()
      .map((error: ValidationError) => {
        if (error.type === "field") {
          return {
            field: (error as FieldValidationError).path,
            message: error.msg,
          };
        }
        return {
          field: "unknown",
          message: error.msg,
        };
      });

    return next(new BadRequestError("Validation failed", formattedErrors));
  }
  next();
};

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/middlewares/Validation.ts"),
      validationMiddlewareContent,
      "utf8"
    );

    /* email template content */
    const emailTemplateContent = `
        import fs from "fs";
import path from "path";
import Handlebars from "handlebars";

const templatesDir = path.join(__dirname, "../templates");

export const getEmailTemplate = (templateName: string, data: any): string => {
  const templatePath = path.join(templatesDir, \`\${templateName}.hbs\`);
  const templateContent = fs.readFileSync(templatePath, "utf-8");
  const template = Handlebars.compile(templateContent);
  return template(data);
};

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/utils/emailTemplate.ts"),
      emailTemplateContent,
      "utf8"
    );

    /* logger content */
    const loggerContent = `
        import { createLogger, format, transports } from "winston";
import { Format } from "logform";
import DailyRotateFile from "winston-daily-rotate-file";

const { combine, timestamp, printf, errors } = format;

// Define the custom format
const logFormat: Format = printf(({ level, message, timestamp, stack }) => {
  return \`\${timestamp} \${level}: \${stack || message}\`;
});

// Create the logger instance
const logger = createLogger({
  level: "info",
  format: combine(timestamp(), errors({ stack: true }), logFormat),
  transports: [
    new transports.Console(),
    new DailyRotateFile({
      filename: "logs/error-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      level: "error",
      maxSize: "20m",
      maxFiles: "14d",
    }),
    new DailyRotateFile({
      filename: "logs/combined-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxSize: "20m",
      maxFiles: "14d",
    }),
  ],
  exceptionHandlers: [
    new DailyRotateFile({
      filename: "logs/exceptions-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxSize: "20m",
      maxFiles: "14d",
    }),
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      filename: "logs/rejections-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxSize: "20m",
      maxFiles: "14d",
    }),
  ],
});

export default logger;

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/utils/logger.ts"),
      loggerContent,
      "utf8"
    );

    /* nodemailer provider content */
    const nodemailerContent = `
        import { EmailOptions } from "../types/email";
import { EmailProvider } from "../types/email";
import nodemailer from "nodemailer";

export class NodemailerProvider implements EmailProvider {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: "sandbox.smtp.mailtrap.io",
      port: 2525,
      auth: {
        user: "",
        pass: "",
      },
    });
  }

  async sendMail(options: EmailOptions) {
    await this.transporter.sendMail(options);
  }
}
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/utils/nodemailerProvider.ts"),
      nodemailerContent,
      "utf8"
    );

    /* email types content */
    const emailTypesContent = `
        export interface EmailOptions {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
}

export interface EmailProvider {
  sendMail(options: EmailOptions): Promise<void>;
}
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/types/email.ts"),
      emailTypesContent,
      "utf8"
    );

    /* time in ms types content */
    const timinMsContent = `
        export interface EmailOptions {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
}

export interface EmailProvider {
  sendMail(options: EmailOptions): Promise<void>;
}
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/types/timeInMS.ts"),
      timinMsContent,
      "utf8"
    );

    /* prisma client content */
    const prismaClientContent = `
        import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient({});

// Extend BigInt prototype in a TypeScript-friendly way
declare global {
  interface BigInt {
    toJSON(): string;
  }
}

BigInt.prototype.toJSON = function () {
  return this.toString();
};

export default prisma;

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/utils/prismaClient.ts"),
      prismaClientContent,
      "utf8"
    );

    /* response content */
    const responseContent = `
        import { Response } from "express";

interface ApiResponse<T> {
  status: string;
  data: T;
  message: string;
  metadata?: Record<string, any>;
}

export interface CookieOptions {
  name: string;
  value: string;
  maxAge?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  path?: string;
}

function successResponse<T>(
  res: Response,
  data: T,
  message = "Success",
  statusCode = 200,
  metadata?: Record<string, any>,
  cookies?: CookieOptions[]
): void {
  const response: ApiResponse<T> = {
    status: "success",
    data: data,
    message: message,
    metadata: metadata,
  };

  if (cookies && cookies.length > 0) {
    cookies.forEach((cookie) => {
      res.cookie(cookie.name, cookie.value, {
        maxAge: cookie.maxAge || 3600000, // Default to 1 hour
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        domain:
          process.env.NODE_ENV === "production" ? ".yourdomain.com" : undefined,
        path: cookie.path || "/",
      });
    });
  }

  res.status(statusCode).json(response);
}

export default successResponse;
    `;
    fs.writeFileSync(
      path.join(projectPath, "src/utils/response.ts"),
      responseContent,
      "utf8"
    );

    /* app.ts content */
    const appTsContent = `
        import express, { NextFunction, Request, Response } from "express";
import errorHandler from "./middlewares/ErrorHandler";
import logger from "./utils/logger";
import router from "./routes/indexRoutes";
import cors from "cors";
import multer from "multer";
import http from "http";
import cookieParser from "cookie-parser";

const app = express();
const server = http.createServer(app);

app.use(cookieParser());
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Accept', 
    'Authorization',
    'Access-Control-Allow-Credentials'
  ]
}));
app.use("/api", router);


app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof multer.MulterError || err.message.includes("Only")) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

app.use(errorHandler);

process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception:", {
    message: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

process.on("unhandledRejection", (reason: any) => {
  logger.error("Unhandled Rejection:", { message: reason.message || reason });
  process.exit(1);
});

async function startServer() {
  try {
    const PORT = 3001;
    server.listen(PORT, () => {
      console.log(\`Server is running on http://localhost:\${PORT}\`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();

    `;
    fs.writeFileSync(
      path.join(projectPath, "src/app.ts"),
      appTsContent,
      "utf8"
    );

    // Step 6: Initialize TypeScript
    console.log("Initializing TypeScript...");
    execSync("npx tsc --init", { stdio: "inherit" });

    console.log("Setting up tsconfig.json...");
    const tsConfigPath = path.join(projectPath, "tsconfig.json");
    const tsConfig = {
      compilerOptions: {
        target: "ES6",
        module: "CommonJS",
        rootDir: "./src",
        outDir: "./dist",
        esModuleInterop: true,
        strict: true,
      },
    };
    fs.writeFileSync(tsConfigPath, JSON.stringify(tsConfig, null, 2), "utf8");

    console.log("TypeScript Express project setup complete!");
  } catch (error) {
    console.error("An error occurred during setup:", error);
  } finally {
    rl.close();
  }
});
