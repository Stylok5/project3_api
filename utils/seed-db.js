import connectToDb from "./db.js";
import mongoose from "mongoose";
import Food from "../models/food.js";
import User from "../models/user.js";
import bcrypt from "bcrypt";
import foodData from "./foodsData.js";

const hashPassword = async (plainTxtPassword) => {
  const hashedPassword = await bcrypt.hash(plainTxtPassword, 10);
  return hashedPassword;
};

const seedingData = {
  users: [
    {
      email: "admin@gmail.com",
      userName: "Administrator",
      password: await hashPassword("adminPassword"),
      role: "admin",
    },
    {
      email: "user@gmail.com",
      userName: "User",
      password: await hashPassword("userPassword"),
      role: "user",
    },
  ],
};

const seedDb = async () => {
  await connectToDb();
  await mongoose.connection.db.dropDatabase();
  console.log("Database connected!");
  await Food.create(foodData.foods);
  await User.create(seedingData.users);
  console.log(`Succesfully created ${seedingData.users}`);
  console.log(`Succesfully created ${foodData.foods}`);
  await mongoose.disconnect();
};
seedDb();
