import { resolveMediaUrl } from "~/utils/media";

export interface Project {
  id: string;
  title: string;
  category: string;
  year: string;
  image: string;
  videoUrl?: string;
  photos?: string[];
  photosUrl?: string | string[];
  aspectRatio?: string;
  description?: string;
  metaData?: Record<string, any>;
  coverVideo?: string;
  type: "video" | "photo";
}

const projectFiles = import.meta.glob("/public/projects/*/project.json", {
  eager: true,
  import: "default",
});
const coverFiles = import.meta.glob("/public/projects/**/*.{jpg,jpeg,png,webp,gif,mp4,webm,mov}");
const videoFiles = import.meta.glob("/public/projects/**/*.{mp4,webm,mov}");

export const projects: Project[] = Object.entries(projectFiles).map(
  ([path, meta]: [string, any]) => {
    const normalizedPath = path.replace(/\\/g, "/");
    const parts = normalizedPath.split("/");
    const id = parts[parts.length - 2];

    // Extract specific properties and keep the rest in metaData
    const {
      title,
      category,
      year,
      date,
      videoUrl,
      photosUrl,
      photosUrls,
      photos,
      coverUrl,
      coverImage,
      aspectRatio,
      description,
      coverVideo,
      ...rest
    } = meta;

    const projectPathPrefix = `/public/projects/${id}/`;
    const assets = Object.keys(coverFiles).filter((f) =>
      f.replace(/\\/g, "/").startsWith(projectPathPrefix),
    );

    let resolvedImage = "";
    let resolvedVideo = videoUrl;
    let coverVideoUrl = coverVideo || "";

    // 1. Resolve Image and Cover Video from assets
    for (const file of assets) {
      const lowerFile = file.toLowerCase();
      const isVideo = lowerFile.endsWith(".mp4") || lowerFile.endsWith(".webm") || lowerFile.endsWith(".mov");
      const isCover = lowerFile.includes("cover.");

      if (isCover) {
        if (isVideo) {
          coverVideoUrl = file.replace("/public", "");
        } else {
          resolvedImage = file.replace("/public", "");
        }
      }
    }

    // 2. Resolve Main Video
    const mainVideoFile = Object.keys(videoFiles).find((f) => {
      const normalizedF = f.replace(/\\/g, "/");
      return normalizedF.startsWith(projectPathPrefix) && !normalizedF.includes("/cover.");
    });

    // If project.json didn't provide a videoUrl, try to find the best match
    if (!resolvedVideo) {
      if (mainVideoFile) {
        resolvedVideo = mainVideoFile.replace("/public", "");
      } else if (coverVideoUrl) {
        resolvedVideo = coverVideoUrl;
      }
    }

    // 3. Resolve Photos from AWS S3 or remote URLs
    let resolvedPhotos: string[] = [];
    const rawPhotosList = photosUrl || photosUrls;

    if (Array.isArray(rawPhotosList)) {
      resolvedPhotos = rawPhotosList.map((url: string) => resolveMediaUrl(url));
    } else if (typeof rawPhotosList === "string" && rawPhotosList.trim()) {
      const trimmedUrl = rawPhotosList.trim();
      if (Array.isArray(photos) && photos.length > 0) {
        const baseUrl = trimmedUrl.endsWith("/") ? trimmedUrl : `${trimmedUrl}/`;
        resolvedPhotos = photos.map((filename: string) => resolveMediaUrl(`${baseUrl}${filename}`));
      } else {
        resolvedPhotos = [resolveMediaUrl(trimmedUrl)];
      }
    } else if (Array.isArray(photos) && photos.length > 0) {
      resolvedPhotos = photos.map((p: string) => resolveMediaUrl(p));
    }

    // Fallback for cover image if no local cover file was found
    if (!resolvedImage) {
      if (coverUrl || coverImage) {
        resolvedImage = resolveMediaUrl(coverUrl || coverImage);
      } else if (resolvedPhotos.length > 0) {
        resolvedImage = resolvedPhotos[0];
      }
    }

    // Determine type: if any video files are present (resolvedVideo/coverVideoUrl) or video fields in meta
    const hasVideo = !!(resolvedVideo || coverVideoUrl || rest.youtubeUrl || rest.vimeoUrl || videoUrl);
    const projectType = hasVideo ? "video" : "photo";

    return {
      id,
      title: title || id,
      category: category || "",
      year: year || (date ? date.split("-")[0] : "") || "",
      image: resolvedImage,
      videoUrl: resolveMediaUrl(resolvedVideo),
      photos: resolvedPhotos,
      photosUrl: rawPhotosList,
      aspectRatio: aspectRatio,
      description: description,
      metaData: rest,
      coverVideo: resolveMediaUrl(coverVideoUrl),
      type: projectType,
    };
  },
).sort((a, b) => b.year.localeCompare(a.year));
