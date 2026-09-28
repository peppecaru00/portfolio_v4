import { c as defineEventHandler, g as getQuery } from '../../_/nitro.mjs';
import 'node:http';
import 'node:https';
import 'node:events';
import 'node:buffer';
import 'node:fs';
import 'node:url';
import 'ipx';
import 'node:path';
import 'node:crypto';

async function fetchPhotosFromS3Folder(folderUrl) {
  if (!folderUrl) return [];
  try {
    const urlObj = new URL(folderUrl);
    const origin = urlObj.origin;
    let prefix = urlObj.pathname.replace(/^\/+/, "");
    if (prefix && !prefix.endsWith("/")) {
      prefix += "/";
    }
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
    const keyMatches = xmlText.matchAll(/<Key>(.*?)<\/Key>/g);
    const imageExtensions = /\.(webp|jpg|jpeg|png|gif|avif|heic)$/i;
    const photoUrls = [];
    for (const match of keyMatches) {
      const key = match[1];
      if (key !== prefix && imageExtensions.test(key)) {
        photoUrls.push(`${origin}/${key}`);
      }
    }
    photoUrls.sort(
      (a, b) => a.localeCompare(b, void 0, { numeric: true, sensitivity: "base" })
    );
    return photoUrls;
  } catch (err) {
    console.error(`[S3] Error fetching folder "${folderUrl}":`, (err == null ? void 0 : err.message) || err);
    return [];
  }
}

const s3Photos_get = defineEventHandler(async (event) => {
  const query = getQuery(event);
  const url = query.url;
  if (!url) {
    return { photos: [] };
  }
  const photos = await fetchPhotosFromS3Folder(url);
  return { photos };
});

export { s3Photos_get as default };
//# sourceMappingURL=s3-photos.get.mjs.map
