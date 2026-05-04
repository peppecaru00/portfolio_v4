import { resolveMediaUrl } from "~/utils/media";

export interface Project {
  id: string;
  title: string;
  category: string;
  year: string;
  image: string;
  videoUrl?: string;
  aspectRatio?: string;
  description?: string;
  metaData?: Record<string, any>;
  coverVideo?: string;
}

const metaFiles = import.meta.glob("/public/projects/*/meta.json", {
  eager: true,
  import: "default",
});
const coverFiles = import.meta.glob("/public/projects/**/*.{jpg,jpeg,png,webp,gif,mp4,webm,mov}");
const videoFiles = import.meta.glob("/public/projects/**/*.{mp4,webm,mov}");

export const projects: Project[] = Object.entries(metaFiles).map(
  ([path, meta]: [string, any]) => {
    const normalizedPath = path.replace(/\\/g, "/");
    const parts = normalizedPath.split("/");
    const id = parts[parts.length - 2];

    // Extract specific properties and keep the rest in metaData
    const {
      title,
      category,
      year,
      videoUrl,
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

    // If meta.json didn't provide a videoUrl, try to find the best match
    if (!resolvedVideo) {
      if (mainVideoFile) {
        resolvedVideo = mainVideoFile.replace("/public", "");
      } else if (coverVideoUrl) {
        resolvedVideo = coverVideoUrl;
      }
    }

    return {
      id,
      title: title || id,
      category: category || "",
      year: year || "",
      image: resolvedImage,
      videoUrl: resolveMediaUrl(resolvedVideo),
      aspectRatio: aspectRatio,
      description: description,
      metaData: rest,
      coverVideo: resolveMediaUrl(coverVideoUrl),
    };
  },
).sort((a, b) => b.year.localeCompare(a.year));
