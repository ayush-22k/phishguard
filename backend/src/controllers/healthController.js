export function getHealth(_request, response) {
  response.status(200).json({
    success: true,
    message: 'PhishGuard API is running',
  });
}
