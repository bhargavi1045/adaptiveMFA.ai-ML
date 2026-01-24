import { Router } from 'express';
import * as AuthController from '../controllers/auth.controller';
import { authenticateJWT } from '../middleware/auth.middleware';

const router = Router();

router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.post('/logout', authenticateJWT, AuthController.logout);
router.get('/status', authenticateJWT, AuthController.status);

export default router;
