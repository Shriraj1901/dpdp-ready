import Razorpay from "razorpay";

// Deliberate mistake for the demo: a secret written into source code (this value is made up).
const RAZORPAY_KEY_SECRET = "Xk9mP2vL8qR4wZ1T7nB3";

export const razorpay = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID!, key_secret: RAZORPAY_KEY_SECRET });
