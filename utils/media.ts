/**
 * Resolves various media URL formats (Google Drive, S3, local paths) 
 * into direct streamable/viewable URLs.
 */
export const resolveMediaUrl = (urlOrId: string | undefined): string => {
  if (!urlOrId) return "";

  // 1. Handle local paths
  if (urlOrId.startsWith("/") && !urlOrId.includes("://")) {
    return urlOrId;
  }

  // 2. Handle Google Drive
  if (urlOrId.includes("drive.google.com") || urlOrId.length === 33 || urlOrId.length === 19) {
    // Extract ID from various Google Drive link formats
    let fileId = "";
    
    // Format: https://drive.google.com/file/d/FILE_ID/view?usp=sharing
    const dMatch = urlOrId.match(/\/d\/([^/]+)/);
    if (dMatch) {
      fileId = dMatch[1];
    } 
    // Format: https://drive.google.com/open?id=FILE_ID
    else {
      const idMatch = urlOrId.match(/[?&]id=([^&]+)/);
      if (idMatch) {
        fileId = idMatch[1];
      } else if (!urlOrId.includes("://") && urlOrId.length > 15) {
        // Assume it's just the ID
        fileId = urlOrId;
      }
    }

    if (fileId) {
      return `https://drive.google.com/uc?export=download&id=${fileId}`;
    }
  }

  // 3. Handle AWS S3
  // S3 links are usually already direct, but we can ensure they are formatted correctly
  // or handle custom patterns if needed.
  if (urlOrId.includes("s3.amazonaws.com") || urlOrId.includes(".s3.") && urlOrId.includes("amazonaws.com")) {
    // Already an S3 URL, ensure it's https
    return urlOrId.replace(/^http:/, "https:");
  }

  // 4. Handle generic URLs (YouTube, Vimeo, etc. should be handled by their respective players, 
  // but for raw <video> tags, we return them as is)
  return urlOrId;
};
