import express from 'express';
import {
  deleteUser,
  getUser,
  getUsers,
  signout,
  test,
  updateUser,
  getAllUsers
} from '../controllers/user.controller.js';
import { verifyToken , verifyAdmin } from '../utils/verifyUser.js';

const router = express.Router();

router.get('/test', test);
router.put('/update/:userId', verifyToken, updateUser);
router.delete("/delete/:id", verifyToken, verifyAdmin, deleteUser);
router.post('/signout', signout);
router.get("/getusers", verifyToken, verifyAdmin, getAllUsers);
router.get('/:userId', getUser);

export default router;