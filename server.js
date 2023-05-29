import express from "express";
import connectToDb from "./utils/db.js";
import logger from "./middleware/logger.js";
import fallback from "./middleware/fallback.js";
import errorHandler from "./middleware/errorhandler.js";
import router from "./router.js";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 2001;
app.use(cors());
app.use(express.json());
app.use(logger);
app.use(router);
app.use(fallback);
app.use(errorHandler);

const startServer = async () => await connectToDb();
{
  await connectToDb();
  app.listen(PORT, () => {
    console.log(`server is working on ${PORT}`);
  });
}
startServer();
