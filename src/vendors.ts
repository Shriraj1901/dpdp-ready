/**
 * Known third-party services that usually receive personal data.
 * "dataTypically" describes common use; what is actually shared depends on how the app is configured.
 * Package names ending in "/*" match a whole npm scope.
 */
export interface Vendor {
  id: string;
  vendor: string;
  category: "Analytics" | "Advertising" | "Session recording" | "Payments" | "Messaging (SMS/email)" | "Customer support" | "Engagement / push" | "Attribution" | "Error monitoring" | "Monitoring" | "Cloud / backend" | "Authentication" | "AI model provider" | "Maps / location" | "Bot protection" | "Media hosting" | "Search" | "Fonts / CDN";
  dataTypically: string;
  packages: string[];
  domains: string[];
  /** True for categories that normally need consent before running (non-essential tracking). */
  tracking: boolean;
}

export const VENDORS: Vendor[] = [
  { id: "google-analytics", vendor: "Google Analytics / Tag Manager", category: "Analytics", tracking: true, dataTypically: "IP address, device and browser identifiers, pages viewed, events", packages: ["react-ga", "react-ga4", "vue-gtag", "ngx-google-analytics", "@analytics/google-analytics"], domains: ["googletagmanager.com", "google-analytics.com", "analytics.google.com"] },
  { id: "google-ads", vendor: "Google Ads / DoubleClick", category: "Advertising", tracking: true, dataTypically: "Cookie and device identifiers, browsing activity", packages: [], domains: ["doubleclick.net", "googleadservices.com", "googlesyndication.com"] },
  { id: "meta", vendor: "Meta (Facebook) Pixel / SDK", category: "Advertising", tracking: true, dataTypically: "Browsing events, device data, hashed emails/phones if advanced matching is on", packages: ["react-facebook-pixel", "facebook-nodejs-business-sdk", "react-native-fbsdk-next", "facebook_app_events", "facebook-business"], domains: ["connect.facebook.net", "facebook.com/tr"] },
  { id: "linkedin-insight", vendor: "LinkedIn Insight Tag", category: "Advertising", tracking: true, dataTypically: "Browsing activity linked to LinkedIn members", packages: [], domains: ["snap.licdn.com", "px.ads.linkedin.com"] },
  { id: "tiktok-pixel", vendor: "TikTok Pixel", category: "Advertising", tracking: true, dataTypically: "Browsing events, device data", packages: [], domains: ["analytics.tiktok.com"] },
  { id: "x-pixel", vendor: "X (Twitter) Pixel", category: "Advertising", tracking: true, dataTypically: "Browsing events, device data", packages: [], domains: ["static.ads-twitter.com", "analytics.twitter.com"] },
  { id: "firebase", vendor: "Google Firebase", category: "Cloud / backend", tracking: false, dataTypically: "Account data, device IDs, usage events, push tokens (depends on products used)", packages: ["firebase", "firebase-admin", "@react-native-firebase/*", "firebase_core", "firebase_analytics", "firebase_auth"], domains: ["firebaseio.com", "firebaseapp.com"] },
  { id: "segment", vendor: "Segment", category: "Analytics", tracking: true, dataTypically: "User IDs, traits (often email/name), events", packages: ["@segment/analytics-next", "@segment/analytics-node", "analytics-node", "@segment/analytics-react-native", "segment-analytics-python"], domains: ["cdn.segment.com", "api.segment.io"] },
  { id: "mixpanel", vendor: "Mixpanel", category: "Analytics", tracking: true, dataTypically: "User IDs, profile properties, events, IP-based location", packages: ["mixpanel", "mixpanel-browser", "mixpanel-react-native"], domains: ["cdn.mxpnl.com", "api-js.mixpanel.com"] },
  { id: "amplitude", vendor: "Amplitude", category: "Analytics", tracking: true, dataTypically: "User IDs, device IDs, events, IP-based location", packages: ["@amplitude/*", "amplitude-js", "amplitude-analytics"], domains: ["cdn.amplitude.com", "api2.amplitude.com"] },
  { id: "posthog", vendor: "PostHog", category: "Analytics", tracking: true, dataTypically: "User IDs, events, optional session recordings", packages: ["posthog-js", "posthog-node", "posthog", "posthog-react-native"], domains: ["posthog.com"] },
  { id: "vercel-analytics", vendor: "Vercel Analytics", category: "Analytics", tracking: false, dataTypically: "Page views, device and country data", packages: ["@vercel/analytics", "@vercel/speed-insights"], domains: [] },
  { id: "hotjar", vendor: "Hotjar", category: "Session recording", tracking: true, dataTypically: "Session recordings, clicks, form interactions", packages: ["@hotjar/browser", "react-hotjar"], domains: ["static.hotjar.com", "script.hotjar.com"] },
  { id: "clarity", vendor: "Microsoft Clarity", category: "Session recording", tracking: true, dataTypically: "Session recordings, clicks, scrolls", packages: ["@microsoft/clarity", "react-microsoft-clarity"], domains: ["clarity.ms"] },
  { id: "logrocket", vendor: "LogRocket", category: "Session recording", tracking: true, dataTypically: "Session recordings, network requests, user identity if set", packages: ["logrocket", "logrocket-react"], domains: [] },
  { id: "fullstory", vendor: "FullStory", category: "Session recording", tracking: true, dataTypically: "Session recordings, user identity if set", packages: ["@fullstory/browser", "@fullstory/react-native"], domains: ["fullstory.com"] },
  { id: "intercom", vendor: "Intercom", category: "Customer support", tracking: false, dataTypically: "Name, email, conversation content, browsing activity", packages: ["@intercom/messenger-js-sdk", "react-use-intercom", "intercom-client"], domains: ["widget.intercom.io", "js.intercomcdn.com"] },
  { id: "freshchat", vendor: "Freshworks (Freshchat)", category: "Customer support", tracking: false, dataTypically: "Name, email, phone, conversation content", packages: [], domains: ["wchat.freshchat.com"] },
  { id: "razorpay", vendor: "Razorpay", category: "Payments", tracking: false, dataTypically: "Name, email, phone, payment details", packages: ["razorpay", "react-native-razorpay", "razorpay_flutter"], domains: ["checkout.razorpay.com"] },
  { id: "stripe", vendor: "Stripe", category: "Payments", tracking: false, dataTypically: "Name, email, billing address, payment details", packages: ["stripe", "@stripe/stripe-js", "@stripe/react-stripe-js", "@stripe/stripe-react-native"], domains: ["js.stripe.com"] },
  { id: "cashfree", vendor: "Cashfree Payments", category: "Payments", tracking: false, dataTypically: "Name, email, phone, payment details", packages: ["cashfree-pg", "@cashfreepayments/cashfree-js"], domains: [] },
  { id: "twilio", vendor: "Twilio", category: "Messaging (SMS/email)", tracking: false, dataTypically: "Phone numbers, message content", packages: ["twilio"], domains: [] },
  { id: "sendgrid", vendor: "SendGrid", category: "Messaging (SMS/email)", tracking: false, dataTypically: "Email addresses, names, email content", packages: ["@sendgrid/mail", "@sendgrid/client", "sendgrid"], domains: [] },
  { id: "mailchimp", vendor: "Mailchimp", category: "Messaging (SMS/email)", tracking: false, dataTypically: "Email addresses, names, campaign activity", packages: ["@mailchimp/mailchimp_marketing", "@mailchimp/mailchimp_transactional", "mailchimp3"], domains: [] },
  { id: "resend", vendor: "Resend", category: "Messaging (SMS/email)", tracking: false, dataTypically: "Email addresses, email content", packages: ["resend"], domains: [] },
  { id: "aws-ses", vendor: "Amazon SES", category: "Messaging (SMS/email)", tracking: false, dataTypically: "Email addresses, email content", packages: ["@aws-sdk/client-ses", "@aws-sdk/client-sesv2"], domains: [] },
  { id: "aws", vendor: "Amazon Web Services", category: "Cloud / backend", tracking: false, dataTypically: "Whatever your app stores or processes there", packages: ["@aws-sdk/*", "aws-sdk", "boto3"], domains: [] },
  { id: "gcp", vendor: "Google Cloud", category: "Cloud / backend", tracking: false, dataTypically: "Whatever your app stores or processes there", packages: ["@google-cloud/*", "google-cloud-storage", "google-cloud-firestore", "google-cloud-bigquery"], domains: [] },
  { id: "supabase", vendor: "Supabase", category: "Cloud / backend", tracking: false, dataTypically: "Database contents, user accounts", packages: ["@supabase/supabase-js", "@supabase/*", "supabase"], domains: [] },
  { id: "auth0", vendor: "Auth0 (Okta)", category: "Authentication", tracking: false, dataTypically: "Email, name, login history, IP address", packages: ["auth0", "@auth0/*", "auth0-python"], domains: [] },
  { id: "clerk", vendor: "Clerk", category: "Authentication", tracking: false, dataTypically: "Email, phone, name, sessions, IP address", packages: ["@clerk/*"], domains: [] },
  { id: "onesignal", vendor: "OneSignal", category: "Engagement / push", tracking: false, dataTypically: "Push tokens, device data, tags", packages: ["react-onesignal", "onesignal-node", "@onesignal/node-onesignal", "react-native-onesignal", "onesignal_flutter"], domains: [] },
  { id: "clevertap", vendor: "CleverTap", category: "Engagement / push", tracking: true, dataTypically: "User profiles, events, device data", packages: ["clevertap-web-sdk", "clevertap-react-native"], domains: [] },
  { id: "moengage", vendor: "MoEngage", category: "Engagement / push", tracking: true, dataTypically: "User profiles, events, device data", packages: ["@moengage/web-sdk", "react-native-moengage"], domains: [] },
  { id: "branch", vendor: "Branch", category: "Attribution", tracking: true, dataTypically: "Device identifiers, install and click attribution", packages: ["branch-sdk", "react-native-branch"], domains: [] },
  { id: "appsflyer", vendor: "AppsFlyer", category: "Attribution", tracking: true, dataTypically: "Device and advertising identifiers, install attribution", packages: ["react-native-appsflyer"], domains: [] },
  { id: "sentry", vendor: "Sentry", category: "Error monitoring", tracking: false, dataTypically: "Error reports, which may include user IDs, IP addresses and request data", packages: ["@sentry/*", "sentry-sdk"], domains: ["sentry.io", "sentry-cdn.com"] },
  { id: "datadog", vendor: "Datadog", category: "Monitoring", tracking: false, dataTypically: "Logs and traces (may contain personal data), RUM sessions", packages: ["dd-trace", "@datadog/*", "ddtrace"], domains: [] },
  { id: "newrelic", vendor: "New Relic", category: "Monitoring", tracking: false, dataTypically: "Logs, traces, browser sessions", packages: ["newrelic"], domains: [] },
  { id: "openai", vendor: "OpenAI", category: "AI model provider", tracking: false, dataTypically: "Any personal data included in prompts or files", packages: ["openai"], domains: [] },
  { id: "anthropic", vendor: "Anthropic", category: "AI model provider", tracking: false, dataTypically: "Any personal data included in prompts or files", packages: ["@anthropic-ai/sdk", "anthropic"], domains: [] },
  { id: "google-ai", vendor: "Google Gemini API", category: "AI model provider", tracking: false, dataTypically: "Any personal data included in prompts or files", packages: ["@google/genai", "@google/generative-ai", "google-generativeai", "google-genai"], domains: ["generativelanguage.googleapis.com"] },
  { id: "deepseek", vendor: "DeepSeek API", category: "AI model provider", tracking: false, dataTypically: "Any personal data included in prompts or files", packages: [], domains: ["api.deepseek.com"] },
  { id: "google-maps", vendor: "Google Maps Platform", category: "Maps / location", tracking: false, dataTypically: "IP address, location queries", packages: ["@react-google-maps/api", "@googlemaps/*", "googlemaps"], domains: ["maps.googleapis.com"] },
  { id: "recaptcha", vendor: "Google reCAPTCHA", category: "Bot protection", tracking: false, dataTypically: "IP address, device and behaviour signals", packages: ["react-google-recaptcha", "react-google-recaptcha-v3"], domains: ["google.com/recaptcha", "recaptcha.net"] },
  { id: "cloudinary", vendor: "Cloudinary", category: "Media hosting", tracking: false, dataTypically: "Uploaded images and files (can include photos of people, documents)", packages: ["cloudinary", "next-cloudinary"], domains: ["res.cloudinary.com"] },
  { id: "algolia", vendor: "Algolia", category: "Search", tracking: false, dataTypically: "Indexed records (may include personal data), search queries", packages: ["algoliasearch", "react-instantsearch"], domains: [] },
  { id: "google-fonts", vendor: "Google Fonts", category: "Fonts / CDN", tracking: false, dataTypically: "Visitor IP address and browser details", packages: [], domains: ["fonts.googleapis.com", "fonts.gstatic.com"] },
];

export function vendorForPackage(name: string): Vendor | undefined {
  const n = name.trim().toLowerCase();
  return VENDORS.find((v) =>
    v.packages.some((p) => (p.endsWith("/*") ? n.startsWith(p.slice(0, -1)) : n === p.toLowerCase())),
  );
}

/** Matches "connect.facebook.net/en_US/fbevents.js" or "https://www.googletagmanager.com/gtag/js". */
export function vendorForUrl(url: string): Vendor | undefined {
  const u = url.toLowerCase().replace(/^https?:\/\//, "").replace(/^\/\//, "");
  return VENDORS.find((v) =>
    v.domains.some((d) => {
      const [host, ...pathParts] = d.split("/");
      const path = pathParts.length ? `/${pathParts.join("/")}` : "";
      const m = u.match(/^([^/?#]+)(\/[^?#]*)?/);
      if (!m) return false;
      const h = m[1].replace(/:\d+$/, "");
      return (h === host || h.endsWith(`.${host}`)) && (!path || (m[2] ?? "").startsWith(path));
    }),
  );
}

export const CONSENT_TOOLS: { name: string; pattern: RegExp }[] = [
  { name: "CookieYes", pattern: /cookieyes/i },
  { name: "OneTrust", pattern: /onetrust|cookielaw\.org/i },
  { name: "Cookiebot", pattern: /cookiebot/i },
  { name: "Osano", pattern: /osano/i },
  { name: "iubenda", pattern: /iubenda/i },
  { name: "Termly", pattern: /termly/i },
  { name: "Didomi", pattern: /didomi/i },
  { name: "Klaro", pattern: /klaro/i },
  { name: "Usercentrics", pattern: /usercentrics/i },
  { name: "Google Consent Mode", pattern: /gtag\(\s*['"]consent['"]/i },
  { name: "react-cookie-consent", pattern: /react-cookie-consent|cookieconsent|cookie-consent/i },
];
