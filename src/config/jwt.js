const jwtConfig = {
  secret: process.env.JWT_SECRET || 'fallback-secret-key',
  expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  algorithm: 'HS256',
  issuer: 'mental-health-platform',
  audience: 'mental-health-users'
};

module.exports = jwtConfig;