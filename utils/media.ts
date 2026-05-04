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

  // 2. Handle AWS S3
  if (urlOrId.includes("s3.amazonaws.com") || (urlOrId.includes(".s3.") && urlOrId.includes("amazonaws.com"))) {
    return urlOrId.replace(/^http:/, "https:");
  }

  // 3. Handle Google Drive
  if (urlOrId.includes("drive.google.com") || (!urlOrId.includes("://") && (urlOrId.length === 33 || urlOrId.length === 19))) {
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
      } else if (!urlOrId.includes("://") && (urlOrId.length === 33 || urlOrId.length === 19)) {
        // Assume it's just the ID
        fileId = urlOrId;
      }
    }

    if (fileId) {
      return `https://drive.google.com/uc?export=download&id=${fileId}`;
    }
  }

  // 4. Handle generic URLs
  return urlOrId;
};
