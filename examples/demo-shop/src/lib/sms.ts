import twilio from "twilio";

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);

export async function sendOtpSms(phone: string, otp: string) {
  await client.messages.create({ to: phone, from: process.env.TWILIO_FROM, body: `Your Demo Shop code is ${otp}` });
}
