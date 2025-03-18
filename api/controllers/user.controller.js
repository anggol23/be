import bcryptjs from 'bcryptjs';
import { errorHandler } from '../utils/errorHandler.js';
import User from '../models/user.model.js';

export const test = (req, res) => {
  res.json({ message: 'API is working!' });
};

export const signup = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    // Validasi input tidak boleh kosong
    if (!username || !email || !password) {
      return next(errorHandler(400, 'All fields are required'));
    }

    // Pastikan password dikirim dengan benar
    if (typeof password !== 'string' || password.trim() === '') {
      return next(errorHandler(400, 'Password is required and must be a string'));
    }

    // Hash password
    const hashedPassword = bcryptjs.hashSync(password, 10);

    // Buat user baru
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: 'Signup successful' });
  } catch (error) {
    next(error);
  }
};


export const updateUser = async (req, res, next) => {
  try {
    if (req.user.id !== req.params.userId) {
      return next(errorHandler(403, 'You are not allowed to update this user'));
    }

    // Validasi password
    if (req.body.password) {
      if (req.body.password.length < 6) {
        return next(errorHandler(400, 'Password must be at least 6 characters'));
      }
      req.body.password = bcryptjs.hashSync(req.body.password, 10);
    }

    // Validasi username
    if (req.body.username) {
      if (req.body.username.length < 7 || req.body.username.length > 20) {
        return next(errorHandler(400, 'Username must be between 7 and 20 characters'));
      }
      if (req.body.username.includes(' ')) {
        return next(errorHandler(400, 'Username cannot contain spaces'));
      }
      if (req.body.username !== req.body.username.toLowerCase()) {
        return next(errorHandler(400, 'Username must be lowercase'));
      }
      if (!req.body.username.match(/^[a-zA-Z0-9]+$/)) {
        return next(errorHandler(400, 'Username can only contain letters and numbers'));
      }
    }

    // Validasi email (jika ada perubahan)
    if (req.body.email) {
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser && existingUser._id.toString() !== req.params.userId) {
        return next(errorHandler(400, 'Email is already in use'));
      }
    }

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      req.params.userId,
      { $set: req.body },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return next(errorHandler(404, 'User not found'));
    }

    const { password, ...rest } = updatedUser._doc;
    res.status(200).json(rest);
  } catch (error) {
    next(error);
  }
};


// export const deleteUser = async (req, res, next) => {
//   try {
//     if (!req.user.isAdmin && req.user.id !== req.params.userId) {
//       return next(errorHandler(403, 'You are not allowed to delete this user'));
//     }

//     const user = await User.findById(req.params.userId);
//     if (!user) {
//       return next(errorHandler(404, 'User not found'));
//     }

//     await User.findByIdAndDelete(req.params.userId);
//     res.status(200).json({ message: 'User has been deleted' });
//   } catch (error) {
//     next(error);
//   }
// };


export const signout = (req, res, next) => {
  try {
    res
      .clearCookie('access_token')
      .status(200)
      .json('User has been signed out');
  } catch (error) {
    next(error);
  }
};

export const getUsers = async (req, res, next) => {
  try {
    if (!req.user.isAdmin) {
      return next(errorHandler(403, 'You are not allowed to see all users'));
    }

    const startIndex = Number(req.query.startIndex) || 0;
    const limit = Number(req.query.limit) || 9;
    const sortDirection = req.query.sort === 'asc' ? 1 : -1;

    if (isNaN(startIndex) || isNaN(limit)) {
      return next(errorHandler(400, 'Invalid pagination parameters'));
    }

    const users = await User.find()
      .sort({ createdAt: sortDirection })
      .skip(startIndex)
      .limit(limit);

    const totalUsers = await User.countDocuments();

    const oneMonthAgo = new Date();
    oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
    const lastMonthUsers = await User.countDocuments({
      createdAt: { $gte: oneMonthAgo },
    });

    const usersWithoutPassword = users.map(({ _doc }) => {
      const { password, ...rest } = _doc;
      return rest;
    });

    res.status(200).json({
      users: usersWithoutPassword,
      totalUsers,
      lastMonthUsers,
    });
  } catch (error) {
    next(error);
  }
};


export const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return next(errorHandler(404, 'User not found'));
    }
    
    const { password, ...rest } = user._doc;
    res.status(200).json(rest);
  } catch (error) {
    next(error);
  }
};

export const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find({}, "-password"); // Ambil semua user tanpa password
    res.status(200).json({ success: true, users });
  } catch (error) {
    next(errorHandler(500, "Error fetching users"));
  }
};

export const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return next(errorHandler(404, "User not found"));

    await User.findByIdAndDelete(req.params.id);
    res.status(200).json({ success: true, message: "User deleted successfully" });
  } catch (error) {
    next(errorHandler(500, "Internal Server Error"));
  }
};