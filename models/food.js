import mongoose from "mongoose";

const reviewSchema = mongoose.Schema(
  {
    text: { type: String, required: true },
    //stars:{type: Integer, required: true}
    createdBy: { type: mongoose.Schema.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

const foodSchema = mongoose.Schema(
  {
    foodUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    name: { type: String, required: true },
    origin: { type: String, required: true },
    description: { type: String, required: true },
    reviews: [reviewSchema],

    ingredients: { type: String },

  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Food", foodSchema);
