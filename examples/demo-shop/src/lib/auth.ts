import { sendOtpSms } from "./sms";

export async function requestLogin(email: string, phone: string) {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  console.log(`Login requested for ${email}, sending otp ${otp} to ${phone}`);
  await sendOtpSms(phone, otp);
  return { ok: true };
}
