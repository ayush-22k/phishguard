/**
 * PhishGuard Email URL Extractor
 * Safely extracts potential URLs from raw text for downstream analysis.
 */

/**
 * Extracts URLs from a given text string.
 * Uses a robust regex to find strings starting with http://, https://, or www.
 * 
 * @param {string} text - The raw email body
 * @returns {string[]} Array of extracted URL strings
 */
export function extractUrlsFromText(text) {
  if (typeof text !== 'string' || !text.trim()) {
    return [];
  }

  // Regex matches http://, https://, or www. followed by domain and optional path/query/fragment
  // It handles typical URL characters and avoids capturing trailing punctuation like period or comma.
  const urlRegex = /(?:https?:\/\/|www\.)[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;
  
  const matches = text.match(urlRegex) || [];
  
  // Deduplicate and trim trailing punctuation that might have accidentally been caught
  const uniqueUrls = new Set();
  
  for (let url of matches) {
    // Strip trailing punctuation often left by regex when URLs are in sentences
    url = url.replace(/[.,;!?)"']+$/, '');
    
    // If it started with www., prepend https:// so the URL engine parses it consistently
    if (url.toLowerCase().startsWith('www.')) {
      url = `https://${url}`;
    }
    
    uniqueUrls.add(url);
  }
  
  return Array.from(uniqueUrls);
}

