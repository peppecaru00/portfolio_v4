import { fetchPhotosFromS3Folder } from "~/utils/s3";

export default defineEventHandler(async (event) => {
  const query = getQuery(event);
  const url = query.url as string;

  if (!url) {
    return { photos: [] };
  }

  const photos = await fetchPhotosFromS3Folder(url);
  return { photos };
});
