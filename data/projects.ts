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
const coverFiles = import.meta.glob("/public/projects/**/*.{jpg,jpeg,png,webp,mp4,webm,mov}");
const videoFiles = import.meta.glob("/public/projects/**/*.{mp4,webm,mov}");

export const projects: Project[] = Object.entries(metaFiles).map(
  ([path, meta]: [string, any]) => {
    const parts = path.split("/");
    const id = parts[parts.length - 2];

    // Extract specific properties and keep the rest in metaData
    const {
      title,
      category,
      year,
      videoUrl,
      aspectRatio,
      description,
      ...rest
    } = meta;

    const projectPathPrefix = `/public/projects/${id}/`;
    const assets = Object.keys(coverFiles).filter((f) =>
      f.replace(/\\/g, "/").startsWith(projectPathPrefix),
    );

    let resolvedImage = "";
    let resolvedVideo = videoUrl;
    let coverVideoUrl = "";

    // 1. Resolve Image and Cover Video from assets
    for (const file of assets) {
      const lowerFile = file.toLowerCase();
      const isVideo = lowerFile.endsWith(".mp4") || lowerFile.endsWith(".webm");
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
    const mainVideoFile = Object.keys(videoFiles).find((f) => 
      f.startsWith(projectPathPrefix) && !f.includes("/cover.")
    );

    // If meta.json didn't provide a videoUrl, try to find the best match
    if (!resolvedVideo && mainVideoFile) {
      resolvedVideo = mainVideoFile.replace("/public", "");
    }

    return {
      id,
      title: title || id,
      category: category || "",
      year: year || "",
      image: resolvedImage,
      videoUrl: resolvedVideo,
      aspectRatio: aspectRatio,
      description: description,
      metaData: rest,
      coverVideo: coverVideoUrl,
    };
  },
);
