export const UserRolesEnum = {
  ADMIN: "admin",
  USER: "user",
  GUEST: "guest",
} as const;

export const PaymentProviderEnum = {
  UNKNOWN: "unknown",
  RAZORPAY: "razorpay",
  PAYPAL: "paypal",
} as const;

export const CouponTypeEnum = {
  FLAT: "flat",
  PERCENTAGE: "percentage",
} as const;

export const UserAuthType = {
  GOOGLE: "google",
  GITHUB: "github",
  CREDENTIALS: "credentials",
} as const;

export const AvailableUserRoles = Object.values(UserRolesEnum);
export const AvailablePaymentProviders = Object.values(PaymentProviderEnum);
export const AvailableCouponTypes = Object.values(CouponTypeEnum);
export const AvailableAuthTypes = Object.values(UserAuthType);
