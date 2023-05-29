import User from "../models/user.js";
import bcrypt from "bcrypt";
import { JWT_SECRET } from "../consts.js";
import jwt from "jsonwebtoken";

const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    res.status(200).json({ success: true, data: users });
  } catch (err) {
    next(err);
  }
};

const getCurrentUser = async (req, res, next) => {
  try {
    // Get the user ID from the request token (assuming you have implemented authentication middleware)
    const userId = req.currentUser.id;

    // Fetch the user information from the database
    const user = await User.findById(userId);

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Return the user data
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
};

const register = async (req, res, next) => {
  const newUser = req.body;
  try {
    const userExist = await User.findOne({ email: newUser.email });
    if (userExist) {
      return res
        .status(400)
        .json({ message: "User already exists", data: { userExist } });
    }
    if (newUser.password !== newUser.confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }
    //const createdUser = await User.create(newUser)
    //const payload = { id }
    const salt = await bcrypt.genSalt(10);
    newUser.password = await bcrypt.hash(newUser.password, salt);
    await User.create(newUser);
    return res.status(200).json({
      message: `User succesfully registered with ${newUser.password}`,
    });
  } catch (err) {
    next(err);
  }
};

const login = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const userAlreadyExist = await User.findOne({ email });
    console.log(userAlreadyExist);
    if (!userAlreadyExist) {
      return res
        .status(400)
        .json({ message: "User not found", data: userAlreadyExist });
    }
    const comparePasswords = await bcrypt.compare(
      password,
      userAlreadyExist.password
    );
    if (!comparePasswords) {
      return res.status(400).json({ message: "User not found" });
    }
    const payload = {
      id: userAlreadyExist.id,
    };
    const token = jwt.sign(payload, JWT_SECRET);
    return res.status(200).json({
      message: `You have succesfully logged in! `,
      token,
    });
  } catch (err) {
    next(err);
  }
};

export default {
  register,
  login,
  getAllUsers,
  getCurrentUser,
};
