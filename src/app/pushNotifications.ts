import { getToken, getMessaging, isSupported, onMessage, type MessagePayload } from "firebase/messaging";
import { app, isFirebaseConfigured } from "./firebase";

const PUSH_TOKEN_KEY = "secureauth:fcm-token";

const getVapidKey = () => import.meta.env.VITE_FIREBASE_VAPID_KEY as string | undefined;

export const getStoredPushToken = () => {
  try {
    return window.localStorage.getItem(PUSH_TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
};

export const clearStoredPushToken = () => {
  try {
    window.localStorage.removeItem(PUSH_TOKEN_KEY);
  } catch {
    // Ignore storage failures in hardened browsers.
  }
};

export const supportsPushNotifications = async () => {
  if (typeof window === "undefined") return false;
  if (!isFirebaseConfigured || !app) return false;
  if (!("Notification" in window) || !("serviceWorker" in navigator)) return false;
  return isSupported().catch(() => false);
};

export const prepareBrowserPushToken = async (promptPermission: boolean) => {
  if (!(await supportsPushNotifications())) {
    return { status: "unsupported" as const, token: "", permission: "unsupported" as const };
  }

  let permission = Notification.permission;
  if (permission === "default" && promptPermission) {
    permission = await Notification.requestPermission();
  }
  if (permission !== "granted") {
    return { status: "permission-required" as const, token: "", permission };
  }

  const vapidKey = getVapidKey();
  if (!vapidKey) {
    return { status: "missing-vapid-key" as const, token: "", permission };
  }

  const registration = await navigator.serviceWorker.register("/firebase-messaging-sw.js");
  const messaging = getMessaging(app!);
  const token = await getToken(messaging, {
    vapidKey,
    serviceWorkerRegistration: registration,
  });

  if (token) {
    try {
      window.localStorage.setItem(PUSH_TOKEN_KEY, token);
    } catch {
      // Ignore storage failures.
    }
  }

  return { status: "ready" as const, token, permission };
};

export const subscribeToForegroundPushes = async (
  handler: (payload: MessagePayload) => void,
) => {
  if (!(await supportsPushNotifications())) return () => {};
  const messaging = getMessaging(app!);
  return onMessage(messaging, handler);
};
