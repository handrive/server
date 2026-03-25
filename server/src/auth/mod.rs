//! Authentication module: JWT, Google OAuth, Apple Sign In, Email OTP, identity credentials, and middleware.

pub mod apple;
pub mod google;
pub mod identity;
pub mod jwt;
pub mod middleware;
pub mod otp;

pub use identity::IdentityGenerator;
pub use jwt::JwtManager;
pub use middleware::{AuthUser, OptionalAuthUser};
