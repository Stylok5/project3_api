import Food from "../models/food.js";

const createReview = async (req, res, next) => {
  const { text } = req.body;
  const { foodId } = req.params;
  const userId = req.currentUser.id.toString();
  try {
    const findFood = await Food.findById(foodId);
    if (!req.currentUser) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (!findFood) {
      return res.status(404).json({ message: "Id not found" });
    }
    const existingReview = findFood.reviews.find(
      (review) => review.createdBy.toString() === userId
    );
    if (existingReview) {
      return res
        .status(400)
        .json({ message: "You have already added a review" });
    }
    findFood.reviews.push({ text, createdBy: userId });
    await findFood.save();
    return res.status(200).json({ message: "Your review has been added" });
  } catch (err) {
    next(err);
  }
};

const updateReview = async (req, res, next) => {
  const updateText = req.body;
  const userId = req.currentUser.id.toString();
  const { foodId, reviewId } = req.params;

  try {
    const findFood = await Food.findById(foodId);
    if (!findFood) {
      return res.status(404).json({ message: "Id not found" });
    }

    if (!req.currentUser) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const existingReview = findFood.reviews.find(
      (review) => review.createdBy.toString() === userId
    );

    if (!existingReview) {
      return res
        .status(400)
        .json({ message: "You are not the creator of this review" });
    }

    const findReview = findFood.reviews.find(
      (review) => review._id.toString() === reviewId
    );

    if (!findReview) {
      return res
        .status(404)
        .json({ message: `Review ${findReview} not found` });
    }

    // Check if the user is the creator of the review
    if (findReview.createdBy.toString() !== userId) {
      return res.status(403).json({ message: "Access denied" });
    }

    findReview.text = updateText.text;
    await findFood.save();

    return res
      .status(200)
      .json({ msg: "Review successfully updated", data: findReview });
  } catch (err) {
    next(err);
  }
};

const deleteReview = async (req, res, next) => {
  const { foodId, reviewId } = req.params;
  try {
    const findFood = await Food.findById(foodId);
    if (!findFood) {
      return res.status(404).json({ message: "Id not found" });
    }
    if (req.currentUser.role !== "admin") {
      return res.status(401).json({ message: "Unauthorized" });
    }
    findFood.reviews = findFood.reviews.filter(
      (review) => review.id !== reviewId
    );
    await findFood.save();
    return res.status(200).json({ message: "Review succesfully deleted" });
  } catch (err) {
    next(err);
  }
};

export default {
  createReview,
  updateReview,
  deleteReview,
};
