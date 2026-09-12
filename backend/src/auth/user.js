export function toSafeUser(user) {
  return Object.freeze({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role.toUpperCase(),
    isVerified: user.is_verified,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
    lastLoginAt: user.last_login_at,
  });
}
