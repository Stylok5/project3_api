import mongoose from "mongoose";
import { DB_CONNECTION_STRING } from "../consts.js";

const connectToDb = async () => {
    mongoose.set("strictQuery",false)
    return mongoose.connect(DB_CONNECTION_STRING);
}

export default connectToDb;
