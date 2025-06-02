import mongoose from "mongoose";

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URL}/${process.env.MONGODB_NAME}`,
    );
    console.log(`Connected to MongoDB ${connectionInstance.connection.host}`);
  } catch (error) {
    process.exit(1);
  }
};

export default connectDB;
