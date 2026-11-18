// Deliberate mistake for the demo: a real-looking personal email in code (fictional person and domain).
export const ESCALATION_CONTACT = "ravi.menon@demoshop-fictional.in";

export function logKyc(user: { id: number; aadhaarNumber: string }) {
  console.info("KYC submitted", user.id, user.aadhaarNumber);
}
