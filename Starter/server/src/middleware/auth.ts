import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// Define the JWT payload interface
interface JwtPayload {
  id: number;
  email: string;
  username: string;
}

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: { id: number; email: string; username: string };
    }
  }
}

// Create the authenticate middleware
export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  // Get token from Authorization header
  const authHeader = req.headers.authorization;

  // Check if token exists
  if (!authHeader) {
    return res.status(401).json({ message: 'No token provided' });
  }

  // Extract token from "Bearer TOKEN" format
  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  // Verify and decode the token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    
    // Attach user info to req.user
    req.user = {
      id: decoded.id,
      email: decoded.email,
      username: decoded.username
    };
    
    // Call next middleware
    next();
  } catch (error) {
    // If verification fails, return 401
    return res.status(401).json({ message: 'Invalid token' });
  }
};