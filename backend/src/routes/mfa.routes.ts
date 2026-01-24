import { Router } from 'express';
import {
  generateMFAChallenge,
  verifyMFA,
  invalidateMFA
} from '../controllers/mfa.controller';
import {authenticateJWT} from "../middleware/auth.middleware"

const router = Router();

router.post('/challenge', generateMFAChallenge);
router.post('/verify', verifyMFA);             
router.post('/invalidate', authenticateJWT, invalidateMFA); 

export default router;
