import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User';

const validateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No authentication token provided' });
  }

  const secret = process.env.JWT_SECRET;

  if (!secret) {
    console.error('Missing JWT_SECRET');
    return res.status(500).json({ message: 'Internal Server Error' });
  }

  jwt.verify(token, secret, async (err, decodedToken: any) => {
    if (err) {
      console.error('Error verifying token:', err);
      return res.status(403).json({ message: 'Not authorized' });
    }

    try {
      const userExists = await User.exists({ _id: decodedToken.userId });

      if (!userExists) {
        console.error('User not found in the database');
        return res.status(403).json({ message: 'Not authorized' });
      }

      req.userId = decodedToken.userId;
      next();
    } catch (dbError) {
      console.error('Database error:', dbError);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
  });
};

export default validateToken;
