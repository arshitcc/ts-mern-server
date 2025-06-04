import mongoose from "mongoose";
import logger from "../loggers/winston.logger";

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URL}/${process.env.MONGODB_NAME}`,
    );
    logger.info(
      `\n☘️  MongoDB Connected! Db host: ${connectionInstance.connection.host}\n`,
    );
  } catch (error) {
    logger.error("MongoDB Connection Error: ", error);
    process.exit(1);
  }
};

export default connectDB;
