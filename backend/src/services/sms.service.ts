import twilio from "twilio";

const client = twilio(
  process.env.TWILIO_SID!,
  process.env.TWILIO_AUTH_TOKEN!
);

export const sendSMS = async (phone: string, code: string) => {
  await client.messages.create({
    body: `Your MFA code: ${code}`,
    from: process.env.TWILIO_PHONE_NUMBER!,
    to: phone,
  });
};
