/**
 * Utility functions for AWS S3 folder resolution and photo fetching.
 */

export const isS3FolderUrl = (url: string | undefined): boolean => {
  if (!url) return false;
  return url.endsWith("/") || !/\.(webp|jpg|jpeg|png|gif|avif|heic)$/i.test(url);
};

/**
 * Fetches all photo URLs from an AWS S3 folder URL by querying the ListObjectsV2 API.
 *
 * Example:
 *   fetchPhotosFromS3Folder("https://peppecaruso-portfolio-storage.s3.eu-north-1.amazonaws.com/lauree/")
 */
export async function fetchPhotosFromS3Folder(folderUrl: string): Promise<string[]> {
  if (!folderUrl) return [];

  try {
    const urlObj = new URL(folderUrl);
    const origin = urlObj.origin;
    let prefix = urlObj.pathname.replace(/^\/+/, "");
    if (prefix && !prefix.endsWith("/")) {
      prefix += "/";
    }

    // AWS S3 ListObjectsV2 REST API
    const listUrl = `${origin}/?list-type=2&prefix=${encodeURIComponent(prefix)}`;

    const response = await fetch(listUrl);
    if (!response.ok) {
      if (response.status === 403) {
        console.warn(
          `[S3] Access Denied when listing folder "${prefix}". Ensure "s3:ListBucket" permission is granted in the AWS S3 Bucket Policy.`
        );
      } else {
        console.warn(`[S3] Failed to list S3 folder "${prefix}": HTTP ${response.status}`);
      }
      return [];
    }

    const xmlText = await response.text();

    if (xmlText.includes("<Error>")) {
      const codeMatch = xmlText.match(/<Code>(.*?)<\/Code>/);
      const code = codeMatch ? codeMatch[1] : "UnknownError";
      console.warn(`[S3] S3 returned error <Code>${code}</Code> when listing folder "${prefix}".`);
      return [];
    }

    // Extract all <Key> tags
    const keyMatches = xmlText.matchAll(/<Key>(.*?)<\/Key>/g);
    const imageExtensions = /\.(webp|jpg|jpeg|png|gif|avif|heic)$/i;

    const photoUrls: string[] = [];
    for (const match of keyMatches) {
      const key = match[1];
      // Exclude the folder directory marker itself, keep only images
      if (key !== prefix && imageExtensions.test(key)) {
        photoUrls.push(`${origin}/${key}`);
      }
    }

    // Natural sort so photo_1, photo_2, photo_10 are in proper order
    photoUrls.sort((a, b) =>
      a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })
    );

    return photoUrls;
  } catch (err: any) {
    console.error(`[S3] Error fetching folder "${folderUrl}":`, err?.message || err);
    return [];
  }
}
