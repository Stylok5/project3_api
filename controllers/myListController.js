import User from "../models/user.js";
import Food from "../models/food.js";
import mongoose from "mongoose";
const id = new mongoose.Types.ObjectId();

const addFood = async (req, res, next) => {
  const { foodId } = req.params;
  const userId = req.currentUser.id;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const food = await Food.findById(foodId);
    console.log(food);
    if (!food) {
      return res
        .status(404)
        .json({ success: false, message: "Food not found" });
    }
    if (user.list.some((foodObj) => foodObj._id.toString() === foodId)) {
      return res
        .status(404)
        .json({ success: false, message: "Food already added" });
    }

    user.list.push(food);
    await user.save();

    res.status(200).json({ message: "Food added to your list", data: user });
  } catch (err) {
    next(err);
  }
};

const grabList = async (req, res, next) => {
  const userId = req.currentUser.id;
  const user = await User.findById(userId);
  try {
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    const userList = user.list;
    res.status(200).json({ success: true, foods: userList });
  } catch (err) {
    next(err);
  }
};

const deleteListItem = async (req, res, next) => {
  const userId = req.currentUser.id;
  const { foodId } = req.params;

  try {
    const findUser = await User.findById(userId);
    if (!findUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const initialLength = findUser.list.length;
    findUser.list = findUser.list.filter(
      (listedFood) => listedFood._id.toString() !== foodId
    );
    const finalLength = findUser.list.length;

    if (finalLength === initialLength) {
      return res.status(404).json({ message: "Food not found" });
    }

    await findUser.save();
    return res.status(200).json({ message: "Food removed from list" });
  } catch (err) {
    next(err);
  }
};

const createListFood = async (req, res, next) => {
  const newFood = req.body;
  const userId = req.currentUser.id;

  try {
    if (req.currentUser.role !== "user") {
      return res.status(400).json({ message: "Not authenticated" });
    }
    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    const id = new mongoose.Types.ObjectId();
    const foodItem = { ...newFood, _id: id };
    user.list.push(foodItem);
    await user.save();
    res
      .status(200)
      .json({ message: "You have created a food in your list", foodItem });
  } catch (err) {
    next(err);
  }
};

// const updateFoodList = async (req, res, next) => {
//   const { foodId } = req.params;
//   const userId = req.currentUser.id;

//   try {
//     const findUser = await User.findById(userId);
//     if (!findUser) {
//       return res.status(404).json({ message: "User not found" });
//     }
//     const foodIndex = findUser.list.findIndex(
//       (listedFood) => listedFood._id.toString() === foodId
//     );
//     if (foodIndex === -1) {
//       return res
//         .status(404)
//         .json({ message: `Food with id ${foodId} not found` });
//     }
//     const updatedFood = { ...findUser.list[foodIndex], ...req.body };
//     findUser.list[foodIndex] = updatedFood;

//     await findUser.save();

//     return res.status(200).json({
//       success: true,
//       message: "Food updated",
//       data: updatedFood,
//     });
//   } catch (err) {
//     next(err);
//   }
// };

export default {
  addFood,
  grabList,
  deleteListItem,
  createListFood,
  // updateFoodList,
};
